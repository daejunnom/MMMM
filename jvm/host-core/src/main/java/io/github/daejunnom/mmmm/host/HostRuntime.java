package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import io.github.daejunnom.mmmm.sdk.ActionHandler;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import io.github.daejunnom.mmmm.sdk.RegisteredActionRead;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

/** Bounded transient host dispatch. Durable intents, planning and recovery remain in Rust. */
public final class HostRuntime implements AutoCloseable {
    public static final int MAX_RESULT_BYTES = 256 * 1024;
    private static final int MAX_CACHE_BYTES = 32 * 1024 * 1024;
    private static final int MAX_EFFECT_BYTES = 64 * 1024;
    private static final int MAX_DESCRIPTOR_BYTES = 64 * 1024;
    private static final int MAX_REGISTRATION_BYTES = 8 * 1024 * 1024;
    private static final int INVOCATION_RESERVATION = MAX_RESULT_BYTES * 3 + MAX_EFFECT_BYTES + 512 * 1024;
    private record Action(ObjectNode descriptor, String digest, ActionHandler handler,
                          OptionalCallbacks callbacks, JsonSchema input, JsonSchema output) { }
    private record Key(HostSession session, String invocationId) { }
    private record UndoAssociation(Key sourceRoute, Invocation sourceInvocation, ObjectNode sourceReceipt) { }
    /** Approval rotation does not create a new identity for an already accepted invocation. */
    private record OwnerInvocationKey(String principalRef, String epoch, String gameInstanceId,
                                      String side, UUID playerId, String bindingId, String invocationId) {
        private static OwnerInvocationKey of(HostSession session, Invocation invocation) {
            return new OwnerInvocationKey(session.principalRef(), session.epoch(), session.gameInstanceId(),
                    session.side(), session.playerId(), invocation.bindingId(), invocation.invocationId());
        }
    }
    private static final class Running {
        private final Invocation invocation;
        private final String requestDigest;
        private final CompletableFuture<ProviderResult> result = new CompletableFuture<>();
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final List<ObjectNode> effects = new ArrayList<>();
        private volatile boolean entered;
        private volatile boolean mutationStarted;
        private volatile boolean callbackInvoked;
        private volatile boolean rawCallbackSettled;
        private volatile boolean rawCallbackFailed;
        private volatile boolean providerJobEverAccepted;
        private final AtomicInteger pendingGameThreadTasks = new AtomicInteger();
        private UndoAssociation undoAssociation;
        private volatile ProviderResult latest;
        private volatile boolean providerFinal;
        private final AtomicBoolean polling = new AtomicBoolean();
        private LocalContext dispatchContext;
        private int effectBytes;
        private Running(Invocation invocation) {
            this.invocation = invocation;
            requestDigest = ContractJson.digest(invocation.wire());
        }
    }
    @FunctionalInterface public interface RegistrationApproval {
        /** Approval must come from the trusted policy/contract authority, never the descriptor's own claims. */
        void check(String bindingId, ObjectNode descriptor);
    }
    private final ContractJson contracts;
    private final GameThread thread;
    private final HostAuthority authority;
    private final RegistrationApproval registrationApproval;
    private final Clock clock;
    private final ScopedHandles handles = new ScopedHandles();
    private final ScopedUndoTokens undoTokens = new ScopedUndoTokens();
    private final Map<String, String> undoActions = new HashMap<>();
    private final Map<String, Map<String, Action>> bindings = new HashMap<>();
    private final Map<String, ObjectNode> providers = new HashMap<>();
    private final Map<Key, Running> invocations = new HashMap<>();
    // One index entry per retained Running; the existing invocation reservation bounds its lifetime.
    private final Map<OwnerInvocationKey, Key> invocationOwners = new HashMap<>();
    private final Deque<ObjectNode> events = new ArrayDeque<>();
    private long sequence;
    private int retainedBytes;
    private int registrationBytes;
    private String registrationGeneration;
    private boolean registrationInspection;
    private volatile boolean closed;
    private final AtomicInteger activeReads = new AtomicInteger();

    public HostRuntime(ContractJson contracts, GameThread thread, HostAuthority authority,
                       RegistrationApproval registrationApproval, Clock clock) {
        this.contracts = contracts;
        this.thread = thread;
        this.authority = authority;
        this.registrationApproval = registrationApproval;
        this.clock = clock;
    }

    public synchronized void register(String bindingId, JsonNode descriptor,
                                      ActionHandler handler, OptionalCallbacks callbacks) {
        if (closed || registrationInspection || registrationGeneration != null || !invocations.isEmpty()) throw new ContractException("REGISTRATION_CLOSED", "Registration generation is frozen");
        contracts.validate("ActionDescriptor", descriptor);
        if (!providers.containsKey(bindingId)) throw new ContractException("PROVIDER_UNREGISTERED", "Provider provenance must be registered before its actions");
        ObjectNode value = ContractJson.object(descriptor).deepCopy();
        int descriptorBytes = boundedDescriptor(value);
        registrationApproval.check(bindingId, value.deepCopy());
        if ("external".equals(value.path("side").asText())) {
            throw new ContractException("SIDE_UNSUPPORTED", "The game host does not execute external actions");
        }
        if ("pure".equals(value.path("planning").asText()) && callbacks.prepare() == null
                || "job".equals(value.path("completion").asText()) && callbacks.poll() == null
                || "cooperative".equals(value.path("cancellation").asText()) && callbacks.cancel() == null) {
            throw new ContractException("CALLBACK_MISSING", "Action guarantees require their declared callbacks");
        }
        if (!Set.of("none", "provider_undo").contains(value.path("recovery").asText())) {
            throw new ContractException("RECOVERY_UNSUPPORTED", "Recovery requires a new Coordinator operation and is not exposed by this host generation");
        }
        int actionCount = bindings.values().stream().mapToInt(Map::size).sum();
        if (actionCount >= 1024 || bindings.size() >= 128 && !bindings.containsKey(bindingId)) {
            throw new ContractException("REGISTRATION_LIMIT", "Host registration capacity is exhausted");
        }
        Action action = new Action(value, ContractJson.digest(value), handler, callbacks,
                contracts.compileActionSchema(value.get("inputSchema")), contracts.compileActionSchema(value.get("outputSchema")));
        Map<String, Action> binding = bindings.computeIfAbsent(bindingId, ignored -> new HashMap<>());
        if (binding.putIfAbsent(value.path("actionId").asText(), action) != null) {
            throw new ContractException("ACTION_DUPLICATE", "The binding already has this action ID");
        }
        registrationBytes += descriptorBytes;
        event("registration", bindingId, value.path("actionId").asText());
    }

    public synchronized void registerUndo(String bindingId, String sourceActionId, String undoActionId) {
        if (closed || registrationInspection || registrationGeneration != null || !invocations.isEmpty()) throw new ContractException("REGISTRATION_CLOSED", "Undo registration must precede invocation dispatch");
        Action source = action(bindingId, sourceActionId); Action undo = action(bindingId, undoActionId);
        if (sourceActionId.equals(undoActionId) || !"provider_undo".equals(source.descriptor.path("recovery").asText())
                || undo.callbacks.recover() == null || "read".equals(undo.descriptor.path("effect").asText())
                || !"none".equals(undo.descriptor.path("recovery").asText())) {
            throw new ContractException("RECOVERY_UNSUPPORTED", "Undo requires an explicit nonrecursive registered recovery callback");
        }
        if (undoActions.putIfAbsent(bindingId + "\u0000" + sourceActionId, undoActionId) != null) throw new ContractException("ACTION_DUPLICATE", "Undo relationship is already registered");
    }
    public synchronized ObjectNode undoRegistration(String bindingId, String sourceActionId) {
        Action source = action(bindingId, sourceActionId);
        String undoId = undoActions.get(bindingId + "\u0000" + sourceActionId);
        if (undoId == null) throw new ContractException("RECOVERY_UNSUPPORTED", "Source action has no registered undo relationship");
        Action undo = action(bindingId, undoId);
        ObjectNode result = ContractJson.newObject().put("bindingId", bindingId).put("sourceActionId", sourceActionId)
                .put("sourceActionDigest", source.digest).put("sourceImplementationDigest", source.descriptor.path("implementationDigest").asText())
                .put("undoActionDigest", undo.digest);
        result.set("undoAction", undo.descriptor.deepCopy()); result.set("providerOrigin", providers.get(bindingId).path("origin").deepCopy());
        return result;
    }

    /**
     * Positive role proof from the complete actual Registrar generation. Successful inspection
     * seals registrations; unsupported/incomplete inspection cannot turn absence into ordinary.
     * The caller must authenticate the inspection and bind native source facts separately.
     */
    public synchronized ObjectNode undoRole(String bindingId, String actionId) {
        return undoRole(bindingId, actionId, value -> value);
    }

    /** Platform attestation is completed and byte-bounded before the generation is sealed. */
    public synchronized ObjectNode undoRole(String bindingId, String actionId, UnaryOperator<ObjectNode> trustedAttestation) {
        if (registrationInspection) throw new ContractException("REGISTRATION_CLOSED", "Registrar inspection cannot reenter its generation attestation");
        Action selected = action(bindingId, actionId);
        for (var binding : bindings.entrySet()) for (var entry : binding.getValue().entrySet()) {
            Action registered = entry.getValue();
            boolean source = undoActions.containsKey(binding.getKey() + "\u0000" + entry.getKey());
            boolean inverse = undoActions.entrySet().stream().anyMatch(route ->
                    route.getKey().startsWith(binding.getKey() + "\u0000") && route.getValue().equals(entry.getKey()));
            if ("provider_undo".equals(registered.descriptor.path("recovery").asText()) && !source
                    || registered.callbacks.recover() != null && !inverse) {
                throw new ContractException("RECOVERY_UNSUPPORTED", "Undo role inspection requires a complete registered source and recovery callback generation");
            }
        }
        ObjectNode result = ContractJson.newObject().put("bindingId", bindingId).put("actionId", actionId);
        result.set("selectedAction", selected.descriptor.deepCopy()); result.put("selectedActionDigest", selected.digest);
        result.set("providerOrigin", providers.get(bindingId).path("origin").deepCopy());
        var routes = result.putArray("routes");
        ObjectNode generation = ContractJson.newObject().put("inventoryRevision", inventory().path("inventoryRevision").asText());
        var generationRoutes = generation.putArray("undoRoutes");
        boolean sourceRole = false; boolean inverseRole = false;
        for (var registered : undoActions.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
            int separator = registered.getKey().indexOf('\u0000');
            String routeBinding = registered.getKey().substring(0, separator);
            String sourceId = registered.getKey().substring(separator + 1);
            Action source = action(routeBinding, sourceId); Action undo = action(routeBinding, registered.getValue());
            generationRoutes.add(ContractJson.newObject().put("bindingId", routeBinding).put("sourceActionId", sourceId)
                    .put("sourceActionDigest", source.digest).put("undoActionId", registered.getValue()).put("undoActionDigest", undo.digest));
            if (!routeBinding.equals(bindingId) || !sourceId.equals(actionId) && !registered.getValue().equals(actionId)) continue;
            sourceRole |= sourceId.equals(actionId); inverseRole |= registered.getValue().equals(actionId);
            if (routes.size() >= 64) throw new ContractException("INPUT_LIMIT", "Selected undo role exceeds the finite route limit");
            ObjectNode route = ContractJson.newObject().put("sourceBindingId", routeBinding).put("undoBindingId", routeBinding);
            route.set("sourceAction", source.descriptor.deepCopy()); route.set("undoAction", undo.descriptor.deepCopy());
            route.set("providerOrigin", providers.get(routeBinding).path("origin").deepCopy()); routes.add(route);
        }
        if (sourceRole && inverseRole) throw new ContractException("RECOVERY_UNSUPPORTED", "An action cannot be both a source and recovery-only action");
        result.put("role", inverseRole ? "recovery_only" : sourceRole ? "source" : "ordinary");
        String actualGeneration = ContractJson.digest(generation);
        if (registrationGeneration != null && !registrationGeneration.equals(actualGeneration)) {
            throw new ContractException("REGISTRATION_CHANGED", "Sealed Registrar generation changed");
        }
        result.put("registrationGeneration", actualGeneration);
        if (ContractJson.bytes(result).length > MAX_RESULT_BYTES) throw new ContractException("INPUT_LIMIT", "Selected undo role exceeds its transport byte limit");
        registrationInspection = true;
        try {
            ObjectNode attested = trustedAttestation.apply(result.deepCopy());
            if (attested == null || ContractJson.bytes(attested).length > MAX_RESULT_BYTES) throw new ContractException("INPUT_LIMIT", "Attested undo role exceeds its transport byte limit");
            registrationGeneration = actualGeneration;
            return attested.deepCopy();
        } finally { registrationInspection = false; }
    }

    public synchronized void registerProvider(JsonNode descriptor) {
        if (closed || registrationInspection || registrationGeneration != null || !invocations.isEmpty()) throw new ContractException("REGISTRATION_CLOSED", "Registration generation is frozen");
        contracts.validate("ProviderDescriptor", descriptor);
        ObjectNode value = ContractJson.object(descriptor).deepCopy();
        int descriptorBytes = boundedDescriptor(value);
        if (!value.path("actions").isEmpty()) throw new ContractException("REGISTRATION_INVALID", "Actions must be registered with their concrete handlers");
        String bindingId = value.path("bindingId").asText();
        registrationApproval.check(bindingId, value.deepCopy());
        if (providers.size() >= 128 || providers.putIfAbsent(bindingId, value) != null) {
            throw new ContractException("PROVIDER_DUPLICATE", "Provider binding is duplicated or exceeds its limit");
        }
        registrationBytes += descriptorBytes;
    }

    private int boundedDescriptor(ObjectNode value) {
        int size = ContractJson.bytes(value).length;
        if (size > MAX_DESCRIPTOR_BYTES || registrationBytes > MAX_REGISTRATION_BYTES - size) {
            throw new ContractException("REGISTRATION_LIMIT", "Registration descriptors exceed the host byte limit");
        }
        return size;
    }

    public CompletionStage<ProviderResult> dispatch(HostSession session, Invocation invocation) {
        Action action = action(invocation.bindingId(), invocation.actionId());
        ObjectNode context = verifyInvocation(session, invocation, action);
        Running running;
        synchronized (this) {
            if (closed) throw new ContractException("HOST_DISCONNECTED", "Host generation has ended");
            Key key = new Key(session, invocation.invocationId());
            OwnerInvocationKey owner = OwnerInvocationKey.of(session, invocation);
            Key originalRoute = invocationOwners.get(owner);
            if (originalRoute != null && originalRoute.session != session) {
                throw new ContractException("SESSION_ROUTE_CHANGED", "Invocation belongs to its original paired session route");
            }
            Running previous = invocations.get(key);
            if (previous != null) {
                if (!previous.requestDigest.equals(ContractJson.digest(invocation.wire()))) {
                    throw new ContractException("IDEMPOTENCY_CONFLICT", "Invocation ID already belongs to different immutable input");
                }
                return previous.result.minimalCompletionStage();
            }
            if (ContractJson.bytes(invocation.wire()).length > MAX_RESULT_BYTES) {
                throw new ContractException("INVOCATION_LIMIT", "Invocation exceeds this host's transient cache limit");
            }
            if (invocations.size() >= 4096 || retainedBytes > MAX_CACHE_BYTES - INVOCATION_RESERVATION) {
                throw new ContractException("HOST_CACHE_FULL", "Host dedup capacity is full; existing invocation evidence is retained");
            }
            running = new Running(invocation);
            invocations.put(key, running);
            invocationOwners.put(owner, key);
            retainedBytes += INVOCATION_RESERVATION;
            event("queued", invocation.bindingId(), invocation.invocationId());
        }
        GuardedContext local = new GuardedContext(session, invocation, context, action, running, false);
        running.dispatchContext = local;
        try {
            thread.execute(() -> {
                try {
                    local.liveAuthorityCheck(!"read".equals(action.descriptor.path("effect").asText()));
                    authority.checkPreconditions(session, context.deepCopy(), invocation.arguments());
                    running.entered = true;
                    CompletionStage<ProviderResult> stage;
                    if (action.callbacks.recover() != null) {
                        synchronized (HostRuntime.this) {
                            if (!undoActions.entrySet().stream().anyMatch(entry -> entry.getKey().startsWith(invocation.bindingId() + "\u0000") && entry.getValue().equals(invocation.actionId()))) {
                                throw new ContractException("RECOVERY_UNSUPPORTED", "The recovery action has no approved source relationship");
                            }
                        }
                        ScopedUndoTokens.ClaimedUndo claim = undoTokens.claimWithSource(session, invocation);
                        Invocation sourceInvocation = new Invocation(contracts, claim.sourceInvocation());
                        synchronized (HostRuntime.this) {
                            Key sourceRoute = invocationOwners.get(OwnerInvocationKey.of(session, sourceInvocation));
                            Running source = sourceRoute == null ? null : invocations.get(sourceRoute);
                            if (source == null || !source.invocation.wire().equals(sourceInvocation.wire())) {
                                throw new ContractException("RECOVERY_EXPIRED", "Consumed undo material has no exact retained original invocation route");
                            }
                            running.undoAssociation = new UndoAssociation(sourceRoute, sourceInvocation, claim.sourceReceipt());
                        }
                        running.callbackInvoked = true;
                        stage = action.callbacks.recover().recover(invocation, claim.privateToken(), local);
                    } else {
                        running.callbackInvoked = true;
                        stage = action.handler.execute(invocation, local);
                    }
                    if (stage == null) throw new ContractException("OUTPUT_INVALID", "Provider returned no completion stage");
                    CompletionStage<ProviderResult> observedStage = stage.whenComplete((reported, failure) -> {
                        if (reported != null && "job_accepted".equals(reported.status())) running.providerJobEverAccepted = true;
                        running.rawCallbackFailed = failure != null; running.rawCallbackSettled = true;
                    });
                    bounded(observedStage, invocation.deadlineAt()).whenComplete((result, failure) -> finish(session, running, action, local, result, failure));
                } catch (RuntimeException exception) { finish(session, running, action, local, null, exception); }
            });
        } catch (RuntimeException exception) { finish(session, running, action, local, null, exception); }
        return running.result.minimalCompletionStage();
    }

    /** Bounded FN33 callback, independent of durable write dispatch and invocation dedup. */
    public CompletionStage<ProviderResult> registeredRead(HostSession session, RegisteredActionRead request, Instant deadline) {
        Action action = action(request.bindingId(), request.actionId()); session.checkOpen();
        if (!"read".equals(action.descriptor.path("effect").asText())) throw new ContractException("EFFECT_MISMATCH", "Registered read requires an explicitly read-only action");
        if (!action.digest.equals(request.actionDigest()) || !action.descriptor.path("side").asText().equals(session.side())) {
            throw new ContractException("INVOCATION_PIN_MISMATCH", "Read action differs from its actual registration");
        }
        if (action.callbacks.read() == null) throw new ContractException("READ_UNSUPPORTED", "The provider did not register a read callback");
        if (!clock.instant().isBefore(deadline)) throw new ContractException("DEADLINE_EXCEEDED", "Read deadline expired");
        Instant limit = deadline.isBefore(clock.instant().plusSeconds(10)) ? deadline : clock.instant().plusSeconds(10);
        ObjectNode context = session.context(request.contextId()); verifyRequiredContext(context, action);
        ContractJson.validateSchema(action.input, request.arguments());
        if (ContractJson.bytes(request.wire()).length > MAX_RESULT_BYTES) throw new ContractException("INPUT_LIMIT", "Read input exceeds the host limit");
        if (activeReads.incrementAndGet() > 32) { activeReads.decrementAndGet(); throw new ContractException("HOST_READ_LIMIT", "Host read capacity is exhausted"); }
        ReadContext local = new ReadContext(session, request, context, action, limit);
        CompletableFuture<ProviderResult> result = new CompletableFuture<>();
        result.orTimeout(Math.max(1, java.time.Duration.between(clock.instant(), limit).toMillis()), java.util.concurrent.TimeUnit.MILLISECONDS)
                .whenComplete((value, failure) -> { local.complete.set(true); activeReads.decrementAndGet(); });
        try { thread.execute(() -> {
            try {
                local.live();
                CompletionStage<ProviderResult> stage = action.callbacks.read().read(request, local);
                bounded(stage, limit).whenComplete((value, failure) -> {
                    if (failure != null) result.completeExceptionally(failure);
                    else { try {
                        if (value == null || "job_accepted".equals(value.status()) || !"none".equals(value.effects())) throw new ContractException("OUTPUT_INVALID", "Read callback cannot create a job or report mutation");
                        contracts.validate("ProviderResult", value.wire());
                        if ("complete".equals(value.status())) ContractJson.validateSchema(action.output, value.data());
                        if (ContractJson.bytes(value.wire()).length > MAX_RESULT_BYTES) throw new ContractException("OUTPUT_LIMIT", "Read result exceeds its limit");
                        result.complete(value);
                    } catch (RuntimeException exception) { result.completeExceptionally(exception); } }
                });
            } catch (RuntimeException exception) { result.completeExceptionally(exception); }
        }); } catch (RuntimeException exception) { result.completeExceptionally(exception); }
        return result.minimalCompletionStage();
    }

    public CompletionStage<ObjectNode> prepare(HostSession session, Invocation invocation) {
        Action action = action(invocation.bindingId(), invocation.actionId());
        ObjectNode context = verifyInvocation(session, invocation, action);
        if (action.callbacks.prepare() == null || !"pure".equals(action.descriptor.path("planning").asText())) {
            throw new ContractException("PREPARE_UNSUPPORTED", "Provider has no pure preparation callback");
        }
        Running temporary = new Running(invocation);
        GuardedContext local = new GuardedContext(session, invocation, context, action, temporary, true);
        CompletableFuture<ObjectNode> result = new CompletableFuture<>();
        try { thread.execute(() -> {
            try {
                local.liveAuthorityCheck(false);
                CompletionStage<ObjectNode> stage = action.callbacks.prepare().prepare(invocation, local);
                if (stage == null) throw new ContractException("OUTPUT_INVALID", "Prepare returned no completion stage");
                bounded(stage, invocation.deadlineAt()).whenComplete((value, failure) -> {
                    local.complete.set(true);
                    if (failure != null || value == null) result.completeExceptionally(new ContractException("PREPARE_FAILED", "Pure preparation failed"));
                    else {
                        try { ContractJson.bytes(value); result.complete(value.deepCopy()); }
                        catch (RuntimeException exception) { result.completeExceptionally(exception); }
                    }
                });
            } catch (RuntimeException exception) { local.complete.set(true); result.completeExceptionally(exception); }
        }); } catch (RuntimeException exception) { local.complete.set(true); result.completeExceptionally(exception); }
        return result.minimalCompletionStage();
    }

    public synchronized ObjectNode operation(HostSession session, String invocationId) {
        Running running = running(session, invocationId);
        ObjectNode status = ContractJson.newObject().put("invocationId", invocationId)
                .put("dispatched", running.entered).put("cancellationRequested", running.cancelled.get())
                .put("providerCompleted", running.result.isDone());
        if (running.latest != null) status.set("result", running.latest.wire());
        ObjectNode undoReceipt = undoTokens.receipt(session, running.invocation);
        if (undoReceipt != null) status.set("undoTokenRecord", undoReceipt);
        status.put("providerCompleted", running.providerFinal);
        var evidence = status.putArray("effectObservations");
        synchronized (running.effects) { running.effects.forEach(value -> evidence.add(value.deepCopy())); }
        return status;
    }

    /** Original route only: a public receipt snapshot, never the provider's private undo token. */
    public synchronized ObjectNode undoMaterial(HostSession session, ObjectNode installedContext, String invocationId) {
        Running running = running(session, invocationId);
        if (!running.invocation.context().equals(installedContext)) {
            throw new ContractException("STALE_CONTEXT", "Undo source inspection requires its original installed context");
        }
        if (session.playerId() == null) throw new ContractException("EXECUTOR_UNAVAILABLE", "Undo source has no authenticated game player");
        ObjectNode material = ContractJson.newObject().put("authenticatedPlayerId", session.playerId().toString());
        material.set("sourceInvocation", running.invocation.wire());
        String undoId = undoActions.get(running.invocation.bindingId() + "\u0000" + running.invocation.actionId());
        if (undoId == null) material.putNull("registration");
        else material.set("registration", undoRegistration(running.invocation.bindingId(), running.invocation.actionId()));
        ObjectNode receipt = undoTokens.receipt(session, running.invocation);
        if (receipt == null) material.putNull("receipt"); else material.set("receipt", receipt);
        return material;
    }

    /** Actual SDK executor facts; this does not assert restored targets or termination of indirect native effects. */
    public synchronized ObjectNode undoJob(HostSession session, ObjectNode installedContext, String invocationId) {
        Running running = running(session, invocationId);
        if (!running.invocation.context().equals(installedContext)) throw new ContractException("STALE_CONTEXT", "Undo job inspection requires its original installed context");
        Action selected = action(running.invocation.bindingId(), running.invocation.actionId());
        if (selected.callbacks.recover() == null) throw new ContractException("RECOVERY_UNSUPPORTED", "Invocation is not an actually registered undo callback");
        boolean contextClosed = running.dispatchContext instanceof GuardedContext local && local.complete.get();
        int pendingTasks = running.pendingGameThreadTasks.get();
        String executorState = !running.entered ? "not_entered" : "running";
        if (contextClosed) {
            executorState = running.callbackInvoked && running.rawCallbackSettled && pendingTasks == 0
                    && !running.polling.get() && !running.providerJobEverAccepted
                    && "synchronous".equals(selected.descriptor.path("completion").asText()) ? "synchronous_quiescent" : "unknown";
        }
        ObjectNode result = ContractJson.newObject().put("format", "mmmm.host.undo-job/1");
        result.set("invocation", running.invocation.wire()); result.put("invocationDigest", running.requestDigest);
        UndoAssociation association = running.undoAssociation;
        if (association == null) { result.putNull("sourceInvocation"); result.putNull("sourceReceipt"); }
        else {
            Running source = invocations.get(association.sourceRoute());
            if (source == null || !source.invocation.wire().equals(association.sourceInvocation().wire())) {
                throw new ContractException("RECOVERY_EXPIRED", "Undo source route is no longer retained");
            }
            result.set("sourceInvocation", association.sourceInvocation().wire()); result.set("sourceReceipt", association.sourceReceipt().deepCopy());
        }
        result.put("callbackEntered", running.callbackInvoked).put("mutationStarted", running.mutationStarted)
                .put("cancellationRequested", running.cancelled.get()).put("polling", running.polling.get())
                .put("rawCallbackSettled", running.rawCallbackSettled).put("rawCallbackFailed", running.rawCallbackFailed)
                .put("contextClosed", contextClosed).put("pendingGameThreadTasks", pendingTasks)
                .put("providerJobOutstanding", running.providerJobEverAccepted).put("executorState", executorState);
        if (ContractJson.bytes(result).length > MAX_RESULT_BYTES) throw new ContractException("INPUT_LIMIT", "Undo job inspection exceeds its bounded transport size");
        return result;
    }

    public CompletionStage<ObjectNode> cancel(HostSession session, String invocationId) {
        Running running;
        synchronized (this) { running = running(session, invocationId); running.cancelled.set(true); }
        ObjectNode response = ContractJson.newObject().put("invocationId", invocationId).put("cancellationRequested", true)
                .put("terminationConfirmed", !running.entered && running.providerFinal);
        Action action = action(running.invocation.bindingId(), running.invocation.actionId());
        if (action.callbacks.cancel() == null || running.latest == null || running.latest.jobHandle() == null) {
            return CompletableFuture.completedFuture(response);
        }
        String jobHandle = running.latest.jobHandle();
        handles.resolve(session, running.invocation.bindingId(), session.context(running.invocation.contextId()), jobHandle, "job", String.class);
        GuardedContext control = new GuardedContext(session, running.invocation,
                session.context(running.invocation.contextId()), action, running, true);
        control.controlQuery = true;
        CompletableFuture<ObjectNode> result = new CompletableFuture<>();
        try { thread.execute(() -> {
            try {
                control.liveAuthorityCheck(false);
                bounded(action.callbacks.cancel().cancel(jobHandle, control), clock.instant().plusSeconds(10)).whenComplete((value, failure) -> {
                    if (failure == null && value != null) {
                        try {
                            if (ContractJson.bytes(value).length > MAX_RESULT_BYTES) throw new ContractException("OUTPUT_LIMIT", "Cancellation report exceeds its limit");
                            response.set("providerReport", value.deepCopy());
                            result.complete(response);
                        } catch (RuntimeException exception) { result.completeExceptionally(exception); }
                    } else result.completeExceptionally(new ContractException("CANCEL_UNCONFIRMED", "Provider cancellation has no confirmed report"));
                    control.complete.set(true);
                });
            } catch (RuntimeException exception) { control.complete.set(true); result.completeExceptionally(exception); }
        }); } catch (RuntimeException exception) { control.complete.set(true); result.completeExceptionally(exception); }
        return result.minimalCompletionStage();
    }

    public CompletionStage<ObjectNode> poll(HostSession session, String invocationId) {
        Running running;
        synchronized (this) { running = running(session, invocationId); }
        ProviderResult previous = running.latest;
        Action action = action(running.invocation.bindingId(), running.invocation.actionId());
        if (previous == null || !"job_accepted".equals(previous.status()) || running.providerFinal) {
            return CompletableFuture.completedFuture(operation(session, invocationId));
        }
        if (action.callbacks.poll() == null) throw new ContractException("POLL_UNSUPPORTED", "Provider has no polling callback");
        if (!running.polling.compareAndSet(false, true)) return CompletableFuture.completedFuture(operation(session, invocationId));
        GuardedContext control = new GuardedContext(session, running.invocation,
                session.context(running.invocation.contextId()), action, running, true);
        control.controlQuery = true;
        CompletableFuture<ObjectNode> result = new CompletableFuture<>();
        try { thread.execute(() -> {
            try {
                control.liveAuthorityCheck(false);
                handles.resolve(session, running.invocation.bindingId(), session.context(running.invocation.contextId()), previous.jobHandle(), "job", String.class);
                bounded(action.callbacks.poll().poll(previous.jobHandle(), control), clock.instant().plusSeconds(10)).whenComplete((value, failure) -> {
                    try {
                        if (failure == null && value != null) {
                            finish(session, running, action, control, value, null);
                            result.complete(operation(session, invocationId));
                        } else result.completeExceptionally(new ContractException("POLL_FAILED", "Provider polling did not return a valid observation"));
                    } catch (RuntimeException exception) { result.completeExceptionally(exception); }
                    finally { running.polling.set(false); control.complete.set(true); }
                });
            } catch (RuntimeException exception) { running.polling.set(false); control.complete.set(true); result.completeExceptionally(exception); }
        }); } catch (RuntimeException exception) { running.polling.set(false); control.complete.set(true); result.completeExceptionally(exception); }
        return result.minimalCompletionStage();
    }

    public synchronized ObjectNode inventory() {
        ObjectNode result = ContractJson.newObject();
        var array = result.putArray("providers");
        providers.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            ObjectNode provider = entry.getValue().deepCopy();
            var actions = provider.putArray("actions");
            bindings.getOrDefault(entry.getKey(), Map.of()).entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .forEach(item -> actions.add(item.getValue().descriptor.deepCopy()));
            array.add(provider);
        });
        result.put("inventoryRevision", ContractJson.digest(array));
        result.putArray("diagnostics");
        contracts.validate("ProviderInventory", result);
        return result;
    }

    public ObjectNode describe(String bindingId, String actionId) { return action(bindingId, actionId).descriptor.deepCopy(); }
    public synchronized ObjectNode eventsSince(long after) {
        if (after < 0 || after > sequence) throw new ContractException("EVENT_CURSOR_INVALID", "Event cursor is outside this host generation");
        long first = events.isEmpty() ? sequence + 1 : Long.parseLong(events.getFirst().path("sequence").asText());
        ObjectNode result = ContractJson.newObject().put("gap", after < first - 1).put("latestSequence", Long.toString(sequence));
        var array = result.putArray("events");
        events.stream().filter(value -> Long.parseLong(value.path("sequence").asText()) > after).forEach(value -> array.add(value.deepCopy()));
        return result;
    }
    public synchronized long sequence() { return sequence; }
    public ObjectNode hello() { return authority.hello().deepCopy(); }

    public void closeSession(HostSession session) {
        session.close();
        handles.removeSession(session);
        synchronized (this) {
            invocations.forEach((key, running) -> { if (key.session == session) running.cancelled.set(true); });
        }
    }

    @Override public synchronized void close() {
        closed = true;
        invocations.forEach((key, running) -> { running.cancelled.set(true); key.session.close(); });
        handles.clear();
        undoTokens.clear(); undoActions.clear();
        invocationOwners.clear();
        bindings.clear();
        providers.clear();
    }

    private synchronized Action action(String bindingId, String actionId) {
        if (closed) throw new ContractException("HOST_DISCONNECTED", "Host generation has ended");
        Action action = bindings.getOrDefault(bindingId, Map.of()).get(actionId);
        if (action == null) throw new ContractException("ACTION_UNKNOWN", "No registered action matches this binding");
        return action;
    }
    private ObjectNode verifyInvocation(HostSession session, Invocation invocation, Action action) {
        session.checkOpen();
        ObjectNode context = session.context(invocation.contextId());
        if (!context.equals(invocation.context()) || !action.digest.equals(invocation.actionDigest())
                || !action.descriptor.path("implementationDigest").asText().equals(invocation.implementationDigest())
                || !action.descriptor.path("contractVersion").asText().equals(invocation.actionContractVersion())
                || !action.descriptor.path("side").asText().equals(session.side())) {
            throw new ContractException("INVOCATION_PIN_MISMATCH", "Invocation no longer matches the authenticated context or registration");
        }
        if (!clock.instant().isBefore(invocation.deadlineAt())) throw new ContractException("DEADLINE_EXCEEDED", "Invocation deadline elapsed before dispatch");
        ContractJson.validateSchema(action.input, invocation.arguments());
        verifyRequiredContext(context, action);
        return context;
    }
    private void verifyRequiredContext(ObjectNode context, Action action) {
        for (JsonNode required : action.descriptor.path("requiredContext")) {
            String field = switch (required.asText()) {
                case "world" -> "environment"; case "executor" -> "executorHandle"; case "project" -> "projectId";
                case "rotation" -> "rotationDegrees"; case "selection" -> "selectionRef"; default -> required.asText();
            };
            if (!context.has(field) || "world".equals(required.asText()) && !context.path("environment").has("worldId")) {
                throw new ContractException("CONTEXT_INCOMPLETE", "A required action context field is unavailable");
            }
        }
    }

    private void finish(HostSession session, Running running, Action action, GuardedContext local,
                        ProviderResult reported, Throwable failure) {
        ProviderResult result;
        try {
            if (failure != null || reported == null) {
                Throwable cause = failure;
                for (int depth = 0; depth < 8 && (cause instanceof java.util.concurrent.CompletionException || cause instanceof java.util.concurrent.ExecutionException) && cause.getCause() != null; depth++) cause = cause.getCause();
                String code = cause instanceof ContractException exception ? exception.code() : "PROVIDER_FAILED";
                result = ProviderResult.failed(contracts, code, uncertainEffects(running, action));
            } else {
                contracts.validate("ProviderResult", reported.wire());
                if ("complete".equals(reported.status())) ContractJson.validateSchema(action.output, reported.data());
                if (ContractJson.bytes(reported.wire()).length > MAX_RESULT_BYTES) throw new ContractException("OUTPUT_LIMIT", "Provider result exceeds the host limit");
                if ("job_accepted".equals(reported.status())) {
                    running.providerJobEverAccepted = true;
                    if (action.callbacks.poll() == null) throw new ContractException("OUTPUT_INVALID", "Provider accepted a job without a poll callback");
                    handles.resolve(session, running.invocation.bindingId(), session.context(running.invocation.contextId()), reported.jobHandle(), "job", String.class);
                }
                if (running.entered && !"read".equals(action.descriptor.path("effect").asText()) && "none".equals(reported.effects())) {
                    ObjectNode value = reported.wire().put("effects", uncertainEffects(running, action));
                    result = new ProviderResult(contracts, value);
                } else result = reported;
            }
        } catch (RuntimeException exception) {
            result = ProviderResult.failed(contracts, "OUTPUT_INVALID", uncertainEffects(running, action));
        }
        local.complete.set(!"job_accepted".equals(result.status()));
        synchronized (this) {
            if (running.providerFinal) return;
            running.latest = result;
            running.providerFinal = !"job_accepted".equals(result.status());
            if (running.providerFinal && running.dispatchContext instanceof GuardedContext original) original.complete.set(true);
            if (running.result.complete(result)) {
                event("provider_result", running.invocation.bindingId(), running.invocation.invocationId());
            }
        }
    }

    private String uncertainEffects(Running running, Action action) {
        synchronized (running.effects) {
            if (!running.effects.isEmpty()) return "recorded";
        }
        return running.entered && !"read".equals(action.descriptor.path("effect").asText()) ? "unknown" : "none";
    }
    private synchronized Running running(HostSession session, String invocationId) {
        session.checkOpen();
        Running running = invocations.get(new Key(session, invocationId));
        if (running == null) throw new ContractException("INVOCATION_UNKNOWN", "Invocation is not owned by this paired session");
        return running;
    }
    private void threadCheck() {
        if (!thread.isSameThread()) throw new ContractException("WRONG_THREAD", "Live target access requires the host game thread");
    }
    private <T> CompletionStage<T> bounded(CompletionStage<T> stage, Instant deadline) {
        if (stage == null) throw new ContractException("OUTPUT_INVALID", "Provider returned no completion stage");
        long millis = Math.max(1, Math.min(120_000, java.time.Duration.between(clock.instant(), deadline).toMillis()));
        // Timeout bounds the observation and revokes its context. It does not assert that native effects were undone.
        return stage.thenApply(value -> value).toCompletableFuture().orTimeout(millis, java.util.concurrent.TimeUnit.MILLISECONDS);
    }
    private synchronized void event(String kind, String binding, String subject) {
        if (sequence == Long.MAX_VALUE) throw new ContractException("EVENT_SEQUENCE_EXHAUSTED", "Host event sequence exhausted");
        events.addLast(ContractJson.newObject().put("sequence", Long.toString(++sequence)).put("kind", kind)
                .put("bindingId", binding).put("subjectId", subject));
        while (events.size() > 1024) events.removeFirst();
    }

    private final class GuardedContext implements LocalContext {
        private final HostSession session;
        private final Invocation invocation;
        private final ObjectNode context;
        private final Action action;
        private final Running running;
        private final boolean readOnly;
        private final AtomicBoolean complete = new AtomicBoolean();
        private boolean controlQuery;
        private GuardedContext(HostSession session, Invocation invocation, ObjectNode context,
                               Action action, Running running, boolean readOnly) {
            this.session = session; this.invocation = invocation; this.context = context;
            this.action = action; this.running = running; this.readOnly = readOnly;
        }
        @Override public String principalRef() { return session.principalRef(); }
        @Override public String sessionEpoch() { return session.epoch(); }
        @Override public ObjectNode executionContext() { checkActive(); return context.deepCopy(); }
        @Override public boolean cancellationRequested() { return running.cancelled.get(); }
        @Override public void requirePermission(String permission) {
            if (!session.permits(permission)) throw new ContractException("PERMISSION_DENIED", "Paired session lacks a required permission");
        }
        @Override public void requireGameThread() { threadCheck(); checkActive(); }
        @Override public void checkActive() {
            session.checkOpen();
            if (complete.get()) throw new ContractException("INVOCATION_FINISHED", "The provider context has already completed");
            if (closed || !authority.ready()) throw new ContractException("HOST_NOT_READY", "Host target is not ready");
            if (!controlQuery && running.cancelled.get()) throw new ContractException("CANCELLATION_REQUESTED", "Invocation cancellation was requested");
            if (!controlQuery && !clock.instant().isBefore(invocation.deadlineAt())) throw new ContractException("DEADLINE_EXCEEDED", "Invocation deadline elapsed");
            if (!session.context(invocation.contextId()).equals(context)) throw new ContractException("CONTEXT_CHANGED", "Installed context changed");
        }
        private void liveAuthorityCheck(boolean write) {
            threadCheck(); checkActive();
            if (write && !session.verifiedWriteProfile()) throw new ContractException("TARGET_PROFILE_UNVERIFIED", "The exact game write profile is not approved");
            Set<String> permissions = new HashSet<>();
            action.descriptor.path("requiredPermissions").forEach(value -> permissions.add(value.asText()));
            permissions.forEach(this::requirePermission);
            authority.check(session, context.deepCopy(), Set.copyOf(permissions), write);
            authority.checkInvocation(session, invocation, write);
        }
        @Override public <T> CompletionStage<T> onGameThread(Supplier<T> callback) {
            CompletableFuture<T> result = new CompletableFuture<>();
            if (running.pendingGameThreadTasks.incrementAndGet() > 32) {
                running.pendingGameThreadTasks.decrementAndGet();
                throw new ContractException("HOST_QUEUE_LIMIT", "Invocation game-thread callback capacity is exhausted");
            }
            try { thread.execute(() -> {
                try { liveAuthorityCheck(false); result.complete(callback.get()); }
                catch (RuntimeException exception) { result.completeExceptionally(exception); }
                finally { running.pendingGameThreadTasks.decrementAndGet(); }
            }); } catch (RuntimeException exception) { running.pendingGameThreadTasks.decrementAndGet(); result.completeExceptionally(exception); }
            return bounded(result, controlQuery ? clock.instant().plusSeconds(10) : invocation.deadlineAt());
        }
        @Override public <T> String createHandle(String type, T value, Class<T> javaType) {
            requireGameThread();
            return handles.create(session, invocation.bindingId(), context, type, value, javaType);
        }
        @Override public <T> T resolveHandle(String token, String type, Class<T> javaType) {
            requireGameThread();
            return handles.resolve(session, invocation.bindingId(), context, token, type, javaType);
        }
        @Override public void recordEffect(ObjectNode observation) {
            threadCheck();
            if (!running.mutationStarted) throw new ContractException("EFFECT_PROTOCOL_INVALID", "Mutation must begin before recording its effect");
            int bytes = ContractJson.bytes(observation).length;
            if (bytes > 16 * 1024) throw new ContractException("EFFECT_LIMIT", "Effect observation exceeds its limit");
            synchronized (running.effects) {
                if (running.effects.size() >= 128 || running.effectBytes > MAX_EFFECT_BYTES - bytes) {
                    throw new ContractException("EFFECT_LIMIT", "Effect observation count or bytes exceed their limit");
                }
                running.effects.add(observation.deepCopy());
                running.effectBytes += bytes;
            }
        }
        @Override public void beginMutation() {
            if (readOnly || "read".equals(action.descriptor.path("effect").asText())) {
                throw new ContractException("EFFECT_NOT_DECLARED", "This context does not permit mutation");
            }
            if (!session.verifiedWriteProfile()) throw new ContractException("TARGET_PROFILE_UNVERIFIED", "The exact game write profile is not approved");
            liveAuthorityCheck(true);
            authority.checkPreconditions(session, context.deepCopy(), invocation.arguments());
            running.mutationStarted = true;
        }
        @Override public ObjectNode captureUndoToken(ObjectNode privateProviderToken) {
            requireGameThread(); liveAuthorityCheck(true);
            String undoActionId;
            synchronized (HostRuntime.this) { undoActionId = undoActions.get(invocation.bindingId() + "\u0000" + invocation.actionId()); }
            if (readOnly || !running.mutationStarted || !"provider_undo".equals(action.descriptor.path("recovery").asText()) || undoActionId == null) {
                throw new ContractException("RECOVERY_UNSUPPORTED", "Undo token capture requires a declared source relationship and actual mutation boundary");
            }
            return undoTokens.capture(session, invocation, undoActionId, privateProviderToken);
        }
    }

    private final class ReadContext implements LocalContext {
        private final HostSession session; private final RegisteredActionRead request; private final ObjectNode context;
        private final Action action; private final Instant deadline; private final AtomicBoolean complete = new AtomicBoolean();
        private ReadContext(HostSession session, RegisteredActionRead request, ObjectNode context, Action action, Instant deadline) {
            this.session = session; this.request = request; this.context = context; this.action = action; this.deadline = deadline;
        }
        @Override public String principalRef() { return session.principalRef(); }
        @Override public String sessionEpoch() { return session.epoch(); }
        @Override public ObjectNode executionContext() { checkActive(); return context.deepCopy(); }
        @Override public boolean cancellationRequested() { return complete.get(); }
        @Override public void requirePermission(String permission) {
            if (!session.permits(permission)) throw new ContractException("PERMISSION_DENIED", "Paired read lacks this permission");
        }
        @Override public void checkActive() {
            session.checkOpen();
            if (complete.get()) throw new ContractException("INVOCATION_FINISHED", "Read callback context finished");
            if (closed || !authority.ready()) throw new ContractException("HOST_NOT_READY", "Host target is not ready");
            if (!clock.instant().isBefore(deadline)) throw new ContractException("DEADLINE_EXCEEDED", "Read deadline elapsed");
            if (!session.context(request.contextId()).equals(context)) throw new ContractException("CONTEXT_CHANGED", "Installed read context changed");
        }
        @Override public void requireGameThread() { threadCheck(); checkActive(); }
        private void live() {
            requireGameThread(); Set<String> required = new HashSet<>();
            action.descriptor.path("requiredPermissions").forEach(value -> required.add(value.asText()));
            required.forEach(this::requirePermission); authority.check(session, context.deepCopy(), Set.copyOf(required), false);
        }
        @Override public <T> CompletionStage<T> onGameThread(Supplier<T> callback) {
            CompletableFuture<T> result = new CompletableFuture<>();
            try { thread.execute(() -> { try { live(); result.complete(callback.get()); } catch (RuntimeException exception) { result.completeExceptionally(exception); } }); }
            catch (RuntimeException exception) { result.completeExceptionally(exception); }
            return bounded(result, deadline);
        }
        @Override public <T> String createHandle(String type, T value, Class<T> javaType) { requireGameThread(); return handles.create(session, request.bindingId(), context, type, value, javaType); }
        @Override public <T> T resolveHandle(String token, String type, Class<T> javaType) { requireGameThread(); return handles.resolve(session, request.bindingId(), context, token, type, javaType); }
        @Override public void recordEffect(ObjectNode observation) { throw new ContractException("EFFECT_NOT_DECLARED", "Read callback cannot record mutation"); }
        @Override public void beginMutation() { throw new ContractException("EFFECT_NOT_DECLARED", "Read callback cannot begin mutation"); }
    }
}
