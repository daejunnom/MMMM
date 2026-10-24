package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.host.NativeInvocationReservations;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.time.Clock;
import java.time.Instant;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongConsumer;
import java.util.function.Supplier;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;

/** A fresh exact-purpose PACK operation. It does not reactivate the source installation approval. */
final class NativePackCalibrationRun implements HostDispatcher.PurposeRoute, AutoCloseable {
    static final String PURPOSE = "pack_calibration_run/1";
    static final String TARGET = "calibration-objective-mcalpack";
    private static final String[] STEP_IDS = {"pack-init-objective", "pack-seed-marker", "pack-entry"};
    private static final String[] COMMANDS = {"scoreboard objectives add mcalpack dummy",
            "scoreboard players set #marker mcalpack 7331", "function mmmm_calibration:pack/entry"};
    private static final Set<String> MANIFEST_FIELDS = Set.of("kind", "purpose", "selectionDigest", "hostEpoch",
            "registryGeneration", "runtimeSourceFactsDigest", "programDigest", "sourceBundleDigest", "sourceZipResource",
            "sourceOrigin", "plan", "targetId", "stepGuards");
    private static final int MAX_RAW_BYTES = 256 * 1024, MAX_EVENTS = 4096;
    // Charged once to the host's existing aggregate history budget before its first effect.
    // This is a conservative retained-payload/reference reservation, not a JVM heap quota.
    private static final long HISTORY_RESERVATION = 1024L * 1024 + 6L * MAX_RAW_BYTES + MAX_EVENTS * 256L
            + 2L * 64 * 1024 + 3L * 64 * 256;

    private final ContractJson contracts;
    private final ObjectNode manifest;
    private final String manifestDigest, contextId;
    private final HostSession session;
    private final Clock clock;
    private final NativeCalibrationApproval.Tasks tasks;
    private final NativeCalibrationApproval.Current current;
    private final Consumer<Invocation> retainAccepted;
    private final LongConsumer retainEvidenceBytes;
    private final MinecraftServer server;
    private final Supplier<ServerPlayer> player;
    private final Function<String, ServerLevel> levels;
    private final NativeCalibrationBootstrap.Attempt sourceAttempt;
    private final NativePlanApproval plan;
    private final NativeInvocationReservations reservations;
    private final Map<String, ObjectNode> steps = new HashMap<>();
    private final Map<String, Accepted> accepted = new HashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean(), activated = new AtomicBoolean();
    private final StepFacts[] completedSteps = new StepFacts[3];
    private boolean historyReserved;
    private int retainedEventCount;
    private String operationId;
    private CompletedPackRun completed;

    private static final class Accepted {
        private final Invocation original;
        private final String digest;
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final CompletableFuture<ProviderResult> result = new CompletableFuture<>();
        private Throwable failure;
        private IndependentObjectiveImage before, after;
        private List<Event> partial = List.of();
        private boolean quiescent;
        private boolean commandReturned, singleCallback, queueTerminal, taskTerminal, bodyReturned;
        private Accepted(Invocation original) { this.original = original; digest = ContractJson.digest(original.wire()); }
    }

    /** Actual whole-objective bytes from one current read. There is no JSON or expected-image constructor. */
    static final class IndependentObjectiveImage {
        private final ObjectNode context;
        private final byte[] raw;
        private final String sourceFactsDigest, hostDigest, generation, at;
        private final ObjectNode commandObservation;
        private final long from, to;
        private IndependentObjectiveImage(NativePackCalibrationRun owner, ObjectNode actualContext, byte[] actualRaw, long from, long to) {
            context = actualContext.deepCopy(); raw = actualRaw.clone(); sourceFactsDigest = owner.runtimeSourceFactsDigest();
            hostDigest = owner.hostArtifactDigest(); generation = owner.registryGeneration(); this.from = from; this.to = to;
            at = Instant.now().toString(); commandObservation = noCommandObservation();
        }
        private IndependentObjectiveImage(IndependentObjectiveImage actual, ObjectNode commandObservation) {
            context = actual.context; raw = actual.raw; sourceFactsDigest = actual.sourceFactsDigest; hostDigest = actual.hostDigest;
            generation = actual.generation; at = actual.at; from = actual.from; to = actual.to;
            this.commandObservation = commandObservation.deepCopy();
        }
        ObjectNode context() { return context.deepCopy(); }
        byte[] rawBytes() { return raw.clone(); }
        String sourceFactsDigest() { return sourceFactsDigest; }
        String hostDigest() { return hostDigest; }
        String generation() { return generation; }
        long from() { return from; } long to() { return to; } String observedAt() { return at; }
        ObjectNode commandObservation() { return commandObservation.deepCopy(); }
    }

    /** Original actual observations; a late failure never becomes a completed PACK run. */
    private static final class StepFacts {
        private final Invocation original;
        private final IndependentObjectiveImage before, after;
        private final NativeCommandDispatch.Observation callbacks;
        private final List<Event> events;
        private final byte[] runReceipt;
        private StepFacts(Invocation original, IndependentObjectiveImage before, IndependentObjectiveImage after,
                          NativeCommandDispatch.Observation callbacks, Trace trace) {
            this.original = original; this.before = before; this.after = after; this.callbacks = callbacks;
            events = trace.snapshot(); runReceipt = trace.lastReceipt();
        }
    }

    /** Only the complete native causal path of all three original invocations can issue this token. */
    static final class CompletedPackRun {
        private final Invocation original;
        private final ObjectNode environment, zip;
        private final String sourceDigest, hostDigest, generation, programDigest, bundleDigest, at;
        private final byte[] loadReceipt, runReceipt, frozen;
        private final long from, to;
        private final List<StepFacts> actualSteps;
        private CompletedPackRun(NativePackCalibrationRun owner, Invocation original,
                                 NativeCalibrationBootstrap.PackRunReadiness readiness, StepFacts[] actualSteps, Runnable checkpoint) {
            this.original = original; environment = original.context().path("environment").deepCopy();
            sourceDigest = owner.runtimeSourceFactsDigest(); hostDigest = owner.hostArtifactDigest(); generation = owner.registryGeneration();
            programDigest = owner.programDigest(); bundleDigest = text(owner.manifest, "sourceBundleDigest");
            zip = ContractJson.object(owner.manifest.path("sourceZipResource")).deepCopy();
            this.actualSteps = List.of(actualSteps.clone());
            loadReceipt = readiness.receipt().clone(); runReceipt = actualSteps[2].runReceipt.clone();
            from = actualSteps[0].before.from(); to = actualSteps[2].after.to(); at = Instant.now().toString();
            frozen = ContractJson.canonical(NativePackCalibrationSource.encode(this, checkpoint));
        }
        Invocation original() { return original; }
        ObjectNode environment() { return environment.deepCopy(); }
        String runtimeSourceFactsDigest() { return sourceDigest; } String hostArtifactDigest() { return hostDigest; }
        String registryGeneration() { return generation; } String programDigest() { return programDigest; }
        String sourceBundleDigest() { return bundleDigest; } ObjectNode sourceZipResource() { return zip.deepCopy(); }
        byte[] loadReceipt() { return loadReceipt.clone(); } byte[] runReceipt() { return runReceipt.clone(); }
        long from() { return from; } long to() { return to; } String observedAt() { return at; }
        ObjectNode wire(Runnable checkpoint) {
            return checked(() -> ContractJson.object(ContractJson.parse(frozen)), checkpoint);
        }
    }

    NativePackCalibrationRun(ContractJson contracts, ObjectNode input, HostSession session, Clock clock,
                             NativeCalibrationApproval.Tasks tasks, NativeCalibrationApproval.Current current,
                             Consumer<Invocation> retainAccepted, MinecraftServer server, Supplier<ServerPlayer> player,
                             Function<String, ServerLevel> levels, NativeCalibrationBootstrap.Attempt sourceAttempt,
                             LongConsumer retainEvidenceBytes) {
        this.contracts = Objects.requireNonNull(contracts); this.session = Objects.requireNonNull(session);
        this.clock = Objects.requireNonNull(clock); this.tasks = Objects.requireNonNull(tasks); this.current = Objects.requireNonNull(current);
        this.retainAccepted = Objects.requireNonNull(retainAccepted); this.server = Objects.requireNonNull(server);
        this.player = Objects.requireNonNull(player); this.levels = Objects.requireNonNull(levels);
        this.sourceAttempt = Objects.requireNonNull(sourceAttempt); this.retainEvidenceBytes = Objects.requireNonNull(retainEvidenceBytes);
        bounded(input); manifest = input.deepCopy(); HostDispatcher.exactFields(manifest, MANIFEST_FIELDS);
        if (!"native_pack_calibration_run_approval/1".equals(text(manifest, "kind")) || !PURPOSE.equals(text(manifest, "purpose"))
                || !TARGET.equals(text(manifest, "targetId")) || !session.epoch().equals(text(manifest, "hostEpoch"))
                || session.verifiedWriteProfile()) throw invalid();
        for (String field : Set.of("selectionDigest", "runtimeSourceFactsDigest", "programDigest", "sourceBundleDigest")) sha(manifest, field);
        if (!text(manifest, "registryGeneration").matches("[1-9][0-9]{0,18}")) throw invalid();
        contracts.validate("ResourceRef", manifest.path("sourceZipResource"));
        ObjectNode origin = ContractJson.object(manifest.path("sourceOrigin"));
        HostDispatcher.exactFields(origin, Set.of("operationId", "invocationId", "invocationDigest", "frozenManifestDigest"));
        sha(origin, "invocationDigest"); sha(origin, "frozenManifestDigest");
        if (!sourceAttempt.original().operationId().equals(text(origin, "operationId"))
                || !sourceAttempt.original().invocationId().equals(text(origin, "invocationId"))
                || !ContractJson.digest(sourceAttempt.original().wire()).equals(text(origin, "invocationDigest"))
                || !sourceAttempt.frozenManifestDigest().equals(text(origin, "frozenManifestDigest"))
                || !sourceAttempt.sourceBundleDigest().equals(text(manifest, "sourceBundleDigest"))
                || sourceAttempt.purpose() != NativeCalibrationBootstrap.Purpose.PACK_CASE) throw invalid();
        sourceAttempt.requireActualServer(server);
        ObjectNode inner = ContractJson.object(manifest.path("plan"));
        if (!inner.path("steps").isArray() || inner.path("steps").size() != 3 || !inner.path("nativeExecutions").isArray()
                || !inner.path("nativeExecutions").isEmpty() || !inner.path("contextPins").isArray() || inner.path("contextPins").size() != 1) throw invalid();
        plan = new NativePlanApproval(contracts, inner, clock); reservations = new NativeInvocationReservations(plan.expiresAt(), clock);
        contextId = text(ContractJson.object(inner.path("contextPins").get(0)), "contextId");
        for (int index = 0; index < 3; index++) {
            ObjectNode step = ContractJson.object(inner.path("steps").get(index)).deepCopy();
            if (!STEP_IDS[index].equals(text(step, "stepId")) || !"mmmm:command_execute".equals(text(step, "actionId"))
                    || !contextId.equals(text(step, "contextId")) || !ContractJson.digest(arguments(index)).equals(text(step, "argumentsDigest"))
                    || !oneTarget(step.path("resourcesRead")) || !oneTarget(step.path("resourcesWritten"))) throw invalid();
            steps.put(STEP_IDS[index], step);
        }
        ObjectNode guards = ContractJson.object(manifest.path("stepGuards")); HostDispatcher.exactFields(guards, Set.of(STEP_IDS));
        for (int index = 0; index < 3; index++) {
            ObjectNode guard = ContractJson.object(guards.path(STEP_IDS[index]));
            HostDispatcher.exactFields(guard, index == 0 ? Set.of("kind") : Set.of("kind", "previousStepId"));
            if (!(index == 0 ? "initial_absence" : "actual_previous_after").equals(text(guard, "kind"))
                    || index > 0 && !STEP_IDS[index - 1].equals(text(guard, "previousStepId"))) throw invalid();
        }
        checkContext(session.context(contextId)); manifestDigest = ContractJson.digest(manifest);
    }

    String selectionDigest() { return text(manifest, "selectionDigest"); }
    String planId() { return plan.planId(); } String planHash() { return plan.planHash(); }
    String manifestDigest() { return manifestDigest; } String registryGeneration() { return text(manifest, "registryGeneration"); }
    String runtimeSourceFactsDigest() { return text(manifest, "runtimeSourceFactsDigest"); }
    String programDigest() { return text(manifest, "programDigest"); }
    String hostArtifactDigest() { return text(steps.get(STEP_IDS[0]), "implementationDigest"); }
    NativeCalibrationBootstrap.Attempt sourceAttempt() { return sourceAttempt; }

    void activateAfterBridge(HostSession owner, String selection, String digest, Runnable original) {
        original.run(); session.checkOpen();
        if (owner != session || closed.get() || !selectionDigest().equals(selection) || !manifestDigest.equals(digest)) throw invalid();
        current.check(session, session.context(contextId), original, false); original.run();
        if (!activated.compareAndSet(false, true)) throw invalid();
        try { original.run(); } catch (RuntimeException | Error failure) { close(); throw failure; }
    }

    @Override public CompletionStage<ObjectNode> prepare(HostSession owner, Invocation original, HostDispatcher.InspectionControl request) {
        return submit(request, () -> {
            Runnable control = control(owner, original, request, new AtomicBoolean(), false); int index = validate(original, control);
            synchronized (this) { checkStepOrder(index, original); }
            NativeCommandDispatch.requireIdle(server); ServerLevel actualLevel = actualLevel(original.context());
            var readiness = sourceAttempt.packRunReadiness(server, actualLevel, session, original.context(), control);
            IndependentObjectiveImage before = observeObjective(original.context(), actualLevel, control); checkBefore(index, before);
            readiness.checkCurrent(control); check(original, control, true);
            ObjectNode result = ContractJson.newObject().put("format", "mmmm.native.pack-calibration-ready/1")
                    .put("invocationId", original.invocationId()).put("invocationDigest", ContractJson.digest(original.wire()))
                    .put("programDigest", programDigest());
            result.set("targetImages", NativePackCalibrationSource.targetImages(before, control)); bounded(result); return result;
        });
    }

    @Override public CompletionStage<ProviderResult> dispatch(HostSession owner, Invocation original, HostDispatcher.InspectionControl request) {
        var result = new CompletableFuture<ProviderResult>(); var active = new AtomicReference<Accepted>();
        var newlyAdmitted = new AtomicReference<Accepted>();
        request.whenStopped(() -> {
            if (!result.isDone()) { Accepted actual = active.get(); if (actual != null) actual.cancelled.set(true); result.cancel(false); }
        });
        tasks.submit(() -> {
            try {
                Runnable admission = control(owner, original, request, new AtomicBoolean(), false); int index = validate(original, admission);
                Accepted previous;
                synchronized (this) { previous = accepted.get(original.invocationId()); }
                if (previous != null) {
                    if (!previous.digest.equals(ContractJson.digest(original.wire()))) throw invalid();
                    requireReservation(original, true); active.set(previous); copy(previous.result, result); return null;
                }
                NativeCommandDispatch.requireIdle(server); ServerLevel actualLevel = actualLevel(original.context());
                var readiness = sourceAttempt.packRunReadiness(server, actualLevel, session, original.context(), admission);
                IndependentObjectiveImage before = observeObjective(original.context(), actualLevel, admission); checkBefore(index, before);
                Accepted admitted;
                synchronized (this) {
                    if (closed.get() || accepted.containsKey(original.invocationId()) || accepted.size() >= 3) throw invalid();
                    checkStepOrder(index, original);
                    var candidate = reservations.inspect(original, true);
                    // Reserve aggregate host space and publish actual identity before the original effect.
                    if (!historyReserved) {
                        retainEvidenceBytes.accept(HISTORY_RESERVATION + 3L * ContractJson.canonical(manifest).length); historyReserved = true;
                    }
                    reservations.admit(candidate); admitted = new Accepted(original); accepted.put(original.invocationId(), admitted);
                    if (operationId == null) operationId = original.operationId();
                    active.set(admitted); newlyAdmitted.set(admitted); retainAccepted.accept(original);
                }
                admitted.before = before;
                copy(admitted.result, result);
                Runnable execution = control(owner, original, request, admitted.cancelled, false);
                try { admitted.result.complete(execute(original, index, before, actualLevel, readiness, execution)); }
                catch (CommandSyntaxException | RuntimeException | Error failure) { recordFailure(admitted, failure); admitted.result.completeExceptionally(failure); }
            } catch (RuntimeException | Error failure) {
                Accepted admitted = active.get(); if (admitted != null) { recordFailure(admitted, failure); admitted.result.completeExceptionally(failure); }
                result.completeExceptionally(failure);
            }
            synchronized (this) {
                Accepted actual = newlyAdmitted.get(); if (actual != null) actual.bodyReturned = true;
            }
            return null;
        }).whenComplete((ignored, failure) -> {
            synchronized (this) {
                Accepted actual = newlyAdmitted.get();
                if (actual != null) {
                    // Host Tasks may apply an observation timeout. Only a normal
                    // owner-stage completion after this actual body returned is terminal evidence.
                    if (failure == null && actual.bodyReturned) actual.taskTerminal = true;
                    if (failure != null) recordFailure(actual, failure);
                }
            }
            if (failure != null) result.completeExceptionally(failure);
        });
        return result.minimalCompletionStage();
    }

    private ProviderResult execute(Invocation original, int index, IndependentObjectiveImage preparedBefore, ServerLevel actualLevel,
                                   NativeCalibrationBootstrap.PackRunReadiness readiness, Runnable control) throws CommandSyntaxException {
        Trace trace = new Trace(original, index, actualLevel, readiness, control);
        try {
            check(original, control, true); readiness.checkCurrent(control); NativeCommandDispatch.requireIdle(server);
            IndependentObjectiveImage before = observeObjective(original.context(), actualLevel, control);
            if (!Arrays.equals(preparedBefore.raw, before.raw)) throw failure("PACK_CALIBRATION_TARGET_CHANGED"); checkBefore(index, before);
            synchronized (this) { Accepted actual = accepted.get(original.invocationId()); if (actual != null) actual.before = before; }
            ServerPlayer actualPlayer = player.get();
            if (actualPlayer == null || actualPlayer.level() != actualLevel) throw failure("PACK_CALIBRATION_OWNER_CHANGED");
            CommandSourceStack source = NativeCommands.source(actualPlayer, actualLevel, original.context());
            var parsed = server.getCommands().getDispatcher().parse(new StringReader(COMMANDS[index]), source);
            NativeCommandDispatch.Observation returned;
            try (var scope = NativeCalibrationStageHooks.open(trace)) {
                check(original, control, true); returned = NativeCommandDispatch.executeObserved(server, parsed);
            }
            synchronized (this) {
                Accepted actual = accepted.get(original.invocationId());
                if (actual != null) { actual.commandReturned = true; actual.singleCallback = returned.callbackCount() == 1 && returned.singleReturn() != null; }
            }
            if (returned.callbackCount() != 1 || returned.singleReturn() == null) throw failure("NATIVE_RETURN_UNCONFIRMED");
            trace.requireComplete(returned); readiness.checkCurrent(control); NativeCommandDispatch.requireIdle(server);
            IndependentObjectiveImage after = observeObjective(original.context(), actualLevel, control); check(original, control, true);
            var fact = new StepFacts(original, before, after, returned, trace);
            synchronized (this) {
                if (completedSteps[index] != null) throw invalid(); completedSteps[index] = fact;
                if (index == 2) completed = new CompletedPackRun(this, original, readiness, completedSteps, control);
                Accepted actual = accepted.get(original.invocationId());
                if (actual != null) { actual.after = after; actual.partial = fact.events; actual.quiescent = true; }
            }
            return ProviderResult.complete(contracts, ContractJson.newObject().put("commandReturnInt32", returned.singleReturn())
                    .put("completionClaim", "native_command_return_only"), "unknown");
        } catch (CommandSyntaxException | RuntimeException | Error primary) {
            try { synchronized (this) { Accepted actual = accepted.get(original.invocationId()); if (actual != null) actual.partial = trace.snapshot(); } }
            catch (RuntimeException | Error observation) { preserve(primary, observation); }
            try { preserve(primary, trace.interrupted()); }
            catch (RuntimeException | Error observation) { preserve(primary, observation); }
            try { control.run(); } catch (RuntimeException | Error post) { preserve(primary, post); }
            throw primary;
        }
    }

    @Override public CompletionStage<ObjectNode> poll(HostSession owner, String id, HostDispatcher.InspectionControl request) { return query(owner, id, request, false); }
    @Override public CompletionStage<ObjectNode> cancel(HostSession owner, String id, HostDispatcher.InspectionControl request) { return query(owner, id, request, true); }
    private CompletionStage<ObjectNode> query(HostSession owner, String id, HostDispatcher.InspectionControl request, boolean cancel) {
        return submit(request, () -> {
            Accepted actual; synchronized (this) { actual = accepted.get(id); }
            if (actual == null) throw failure("INVOCATION_UNKNOWN");
            Runnable control = control(owner, actual.original, request, actual.cancelled, true); control.run(); requireReservation(actual.original, false);
            if (cancel) actual.cancelled.set(true);
            boolean confirmed;
            synchronized (this) { confirmed = terminal(actual) && actual.result.isDone() && !actual.result.isCompletedExceptionally(); }
            return ContractJson.newObject().put("invocationId", id).put("status", confirmed ? "complete" : "unknown")
                    .put("effects", "unknown").put("furtherEffectsPossible", !confirmed).put("providerCompleted", confirmed)
                    .put("cancellationRequested", actual.cancelled.get()).put("terminationConfirmed", confirmed);
        });
    }

    /** Fresh read authority supplied by the current pairing; no retired execution gate is reactivated. */
    CompletedPackRun lookupRetained(Invocation actualOriginal, Runnable freshCurrent) {
        return checked(() -> {
            CompletedPackRun actual;
            synchronized (this) {
                actual = completed;
                for (StepFacts fact : completedSteps) {
                    if (fact == null) throw failure("PACK_CALIBRATION_RUN_ISSUER_UNAVAILABLE");
                    Accepted original = accepted.get(fact.original.invocationId());
                    if (original == null || original.original != fact.original || !original.digest.equals(ContractJson.digest(fact.original.wire()))
                            || !terminal(original)) throw failure("PACK_CALIBRATION_RUN_ISSUER_UNAVAILABLE");
                }
            }
            if (actual == null || actualOriginal == null || !ContractJson.digest(actual.original.wire()).equals(ContractJson.digest(actualOriginal.wire())))
                throw failure("PACK_CALIBRATION_RUN_ISSUER_UNAVAILABLE");
            return actual;
        }, freshCurrent);
    }

    IndependentObjectiveImage observeState(Invocation actualOriginal, ObjectNode freshContext, HostSession freshOwner, Runnable freshCurrent) {
        return checked(() -> {
            Accepted actual; synchronized (this) { actual = accepted.get(actualOriginal.invocationId()); }
            if (actual == null || !actual.digest.equals(ContractJson.digest(actualOriginal.wire()))
                    || !sameContextScope(actual.original.context(), freshContext)) throw invalid();
            freshOwner.checkOpen(); ServerLevel level = actualLevel(freshContext);
            NativeCommandDispatch.requireIdle(server);
            IndependentObjectiveImage image = observeObjective(freshContext, level, freshOwner, freshCurrent);
            NativeCommandDispatch.requireIdle(server); freshCurrent.run();
            ObjectNode observation;
            synchronized (this) {
                if (accepted.get(actualOriginal.invocationId()) != actual || !actual.digest.equals(ContractJson.digest(actualOriginal.wire()))) throw invalid();
                boolean terminal = terminal(actual);
                observation = ContractJson.newObject().put("commandReturnObserved", actual.commandReturned)
                        .put("singleCallbackObserved", actual.singleCallback).put("queueTerminalObserved", actual.queueTerminal)
                        .put("actualTaskTerminalObserved", actual.taskTerminal).put("terminationConfirmed", terminal)
                        .put("furtherEffectsPossible", !terminal);
                if (terminal) observation.put("continuationPending", false); else observation.putNull("continuationPending");
            }
            return new IndependentObjectiveImage(image, observation);
        }, freshCurrent);
    }

    /** Current plan preflight only. It creates no Invocation, reservation or command-completion fact. */
    IndependentObjectiveImage observePlanState(ObjectNode freshContext, HostSession freshOwner, Runnable freshCurrent) {
        Objects.requireNonNull(freshContext); Objects.requireNonNull(freshOwner); Objects.requireNonNull(freshCurrent);
        Runnable control = () -> {
            freshCurrent.run();
            if (freshOwner != session || closed.get() || !activated.get() || session.verifiedWriteProfile()
                    || !server.isSameThread() || !clock.instant().isBefore(plan.expiresAt())) throw invalid();
            session.checkOpen();
            if (!freshContext.equals(session.context(contextId))) throw invalid();
            checkContext(freshContext); current.check(session, freshContext, freshCurrent, true); freshCurrent.run();
        };
        return checked(() -> {
            NativeCommandDispatch.requireIdle(server);
            IndependentObjectiveImage actual = observeObjective(freshContext, actualLevel(freshContext), freshOwner, control);
            NativeCommandDispatch.requireIdle(server); control.run(); return actual;
        }, control);
    }

    private IndependentObjectiveImage observeObjective(ObjectNode context, ServerLevel level, Runnable control) {
        return observeObjective(context, level, session, control);
    }
    private IndependentObjectiveImage observeObjective(ObjectNode context, ServerLevel level, HostSession actualOwner, Runnable control) {
        long from = tick();
        byte[] bytes = NativeCalibrationStateReader.currentContext(server, level, actualOwner, context, control::run, (installed, checkpoint) -> {
            if (!contains(installed.path("scope").path("externalTargetIds"), TARGET)) throw invalid();
            ObjectNode raw = NativeTargets.readObjectiveImage(level, "mcalpack", checkpoint::check);
            if (!"known".equals(raw.path("status").asText()) || !"full_target".equals(raw.path("coverage").asText()))
                throw failure("PACK_CALIBRATION_TARGET_INCOMPLETE");
            byte[] encoded = ContractJson.canonical(raw); if (encoded.length > MAX_RAW_BYTES) throw failure("PACK_CALIBRATION_LIMIT"); return encoded;
        });
        control.run(); return new IndependentObjectiveImage(this, context, bytes, from, tick());
    }

    private void checkBefore(int index, IndependentObjectiveImage actual) {
        synchronized (this) {
            if (index == 0) {
                ObjectNode raw = ContractJson.object(ContractJson.parse(actual.raw));
                if (!"absent".equals(raw.path("presence").asText())) throw failure("PACK_CALIBRATION_INITIAL_TARGET_PRESENT");
            } else if (completedSteps[index - 1] == null || !Arrays.equals(completedSteps[index - 1].after.raw, actual.raw))
                throw failure("PACK_CALIBRATION_PREVIOUS_AFTER_CHANGED");
        }
    }
    private void checkStepOrder(int index, Invocation original) {
        if (operationId != null && !operationId.equals(original.operationId()) || completedSteps[index] != null) throw invalid();
        for (int prior = 0; prior < index; prior++) if (completedSteps[prior] == null) throw failure("PACK_CALIBRATION_PREVIOUS_STEP_INCOMPLETE");
        for (Accepted value : accepted.values()) if (value.original.stepId().equals(original.stepId())) throw invalid();
    }
    private Runnable control(HostSession owner, Invocation original, HostDispatcher.InspectionControl request, AtomicBoolean cancellation, boolean history) {
        return () -> {
            request.checkpoint(); if (owner != session || closed.get() || !activated.get() || session.verifiedWriteProfile()) throw invalid(); session.checkOpen();
            if (!server.isSameThread() || !original.context().equals(session.context(contextId))) throw invalid();
            if (!history && cancellation.get()) throw failure("CANCELLATION_REQUESTED");
            if (!history && (!clock.instant().isBefore(original.deadlineAt()) || !clock.instant().isBefore(plan.expiresAt()))) throw failure("DEADLINE_EXCEEDED");
            checkContext(original.context()); current.check(session, original.context(), request::checkpoint, false); request.checkpoint();
        };
    }
    private void check(Invocation original, Runnable control, boolean sources) { control.run(); current.check(session, original.context(), control, sources); control.run(); }
    private int validate(Invocation original, Runnable control) {
        control.run(); ObjectNode step = steps.get(original.stepId()); if (step == null) throw invalid();
        for (String field : Set.of("stepId", "bindingId", "actionId", "actionDigest", "implementationDigest", "argumentsDigest", "contextDigest"))
            if (!step.path(field).equals(original.wire().path(field))) throw invalid();
        int index = index(original.stepId());
        if (!contextId.equals(original.contextId()) || !arguments(index).equals(original.arguments())
                || sourceAttempt.original().operationId().equals(original.operationId())) throw invalid();
        return index;
    }
    private void requireReservation(Invocation original, boolean write) { if (!reservations.containsExact(original)) throw invalid(); reservations.inspect(original, write); }
    private void checkContext(ObjectNode context) {
        if (!plan.principalId().equals(session.principalRef()) || !plan.principalId().equals(context.path("principalRef").asText())
                || !plan.projectId().equals(context.path("projectId").asText()) || !plan.policyRevision().equals(context.path("policyRevision").asText())
                || !contextId.equals(context.path("contextId").asText()) || !contains(context.path("scope").path("externalTargetIds"), TARGET)
                || !manifest.path("plan").path("contextPins").get(0).path("environment").equals(context.path("environment"))) throw invalid();
        for (ObjectNode step : steps.values()) if (!step.path("contextDigest").equals(context.path("contextDigest"))) throw invalid();
    }
    private ServerLevel actualLevel(ObjectNode context) {
        ServerLevel level = levels.apply(context.path("dimension").asText());
        if (level == null || level.getServer() != server || server.getLevel(level.dimension()) != level) throw invalid(); return level;
    }
    private static boolean sameContextScope(ObjectNode original, ObjectNode current) {
        for (String field : Set.of("principalRef", "projectId", "dimension", "environment")) if (!original.path(field).equals(current.path(field))) return false;
        return contains(original.path("scope").path("externalTargetIds"), TARGET) && contains(current.path("scope").path("externalTargetIds"), TARGET);
    }
    private static ObjectNode noCommandObservation() {
        return ContractJson.newObject().put("commandReturnObserved", false).put("singleCallbackObserved", false)
                .put("queueTerminalObserved", false).put("actualTaskTerminalObserved", false).putNull("continuationPending")
                .put("terminationConfirmed", false).put("furtherEffectsPossible", true);
    }
    private static boolean terminal(Accepted actual) {
        return actual.bodyReturned && actual.taskTerminal && actual.commandReturned && actual.singleCallback
                && actual.queueTerminal && actual.quiescent && actual.failure == null;
    }
    private synchronized void recordFailure(Accepted actual, Throwable failure) {
        if (actual.failure == null) actual.failure = failure; else preserve(actual.failure, failure);
    }
    private static boolean oneTarget(JsonNode values) { return values.isArray() && values.size() == 1 && TARGET.equals(values.get(0).asText()); }
    private static boolean contains(JsonNode values, String expected) { if (!values.isArray()) return false; for (JsonNode value : values) if (value.isTextual() && expected.equals(value.textValue())) return true; return false; }
    private static int index(String step) { for (int index = 0; index < STEP_IDS.length; index++) if (STEP_IDS[index].equals(step)) return index; throw invalid(); }
    private static ObjectNode arguments(int index) { return ContractJson.newObject().put("command", COMMANDS[index]); }
    private static String text(ObjectNode value, String field) { if (!value.path(field).isTextual()) throw invalid(); return value.path(field).textValue(); }
    private static String sha(ObjectNode value, String field) { String result = text(value, field); if (!result.matches("[a-f0-9]{64}")) throw invalid(); return result; }
    private static void bounded(ObjectNode value) { NativeCalibrationRunFacts.bounded(value); }
    private long tick() { return Integer.toUnsignedLong(server.getTickCount()); }
    private <T> CompletionStage<T> submit(HostDispatcher.InspectionControl request, Supplier<T> body) {
        var result = new CompletableFuture<T>(); request.whenStopped(() -> result.cancel(false));
        tasks.submit(() -> { try { result.complete(body.get()); } catch (RuntimeException | Error failure) { result.completeExceptionally(failure); } return null; })
                .whenComplete((ignored, failure) -> { if (failure != null) result.completeExceptionally(failure); }); return result.minimalCompletionStage();
    }
    private static <T> void copy(CompletionStage<T> source, CompletableFuture<T> target) { source.whenComplete((value, failure) -> { if (failure != null) target.completeExceptionally(failure); else target.complete(value); }); }
    private static <T> T checked(Supplier<T> read, Runnable checkpoint) { checkpoint.run(); return NativeCalibrationStateReader.checked(read, checkpoint::run); }
    private static void preserve(Throwable primary, Throwable additional) { if (additional != null && additional != primary) try { primary.addSuppressed(additional); } catch (RuntimeException | Error ignored) { } }
    private static ContractException invalid() { return failure("PACK_CALIBRATION_APPROVAL_INVALID"); }
    private static ContractException failure(String code) { return new ContractException(code, "Actual PACK calibration is unavailable, incomplete or changed"); }
    @Override public synchronized void close() {
        closed.set(true);
        for (Accepted actual : accepted.values()) actual.cancelled.set(true);
    }

    private record Event(String kind, int sequence, long tick, Object owner, Object source, Object context, Object frame,
                         Object entry, Object queueEntry, Object action, Throwable failure) { }

    /** Object relationships are observed here; only the native48 gate checks the closed captured recipes. */
    private final class Trace implements NativeCalibrationStageHooks.Listener {
        private final Invocation original;
        private final int step;
        private final ServerLevel level;
        private final NativeCalibrationBootstrap.PackRunReadiness readiness;
        private final Runnable control;
        private final List<Event> events = new ArrayList<>();
        private final IdentityHashMap<Object, Boolean> references = new IdentityHashMap<>();
        private final List<Schedule> schedules = new ArrayList<>();
        private final IdentityHashMap<Object, Task> tasks = new IdentityHashMap<>();
        private final IdentityHashMap<Object, Object> instantiated = new IdentityHashMap<>();
        private final ArrayDeque<Task> entered = new ArrayDeque<>();
        private Object executionContext;
        private byte[] receipt;
        private boolean queueComplete, nativeComplete, nativeStarted;
        private int selectedEntries;
        private record Schedule(Object call, Object function, Object source, Object context, Object parent, Object child,
                                List<?> entries, Object provider) { }
        private final class Task {
            private final Schedule schedule;
            private final Object frame, entry, queueEntry, action;
            private boolean executed;
            private Task(Schedule schedule, Object frame, Object entry, Object queueEntry, Object action) {
                this.schedule = schedule; this.frame = frame; this.entry = entry; this.queueEntry = queueEntry; this.action = action;
            }
        }
        private Trace(Invocation original, int step, ServerLevel level, NativeCalibrationBootstrap.PackRunReadiness readiness, Runnable control) {
            this.original = original; this.step = step; this.level = level; this.readiness = readiness; this.control = control;
        }
        private void checkpoint() { check(original, control, true); readiness.checkCurrent(control); }
        private List<Event> snapshot() { return List.copyOf(events); }
        private byte[] lastReceipt() {
            if (step != 2) return new byte[0];
            if (!nativeComplete || receipt == null) throw failure("PACK_CALIBRATION_RUN_ISSUER_UNAVAILABLE"); return receipt.clone();
        }
        private void requireComplete(NativeCommandDispatch.Observation actualCallbacks) {
            checkpoint();
            if (!queueComplete || !entered.isEmpty()) throw failure("PACK_CALIBRATION_QUEUE_INCOMPLETE");
            for (Task task : tasks.values()) if (!task.executed) throw failure("PACK_CALIBRATION_QUEUE_INCOMPLETE");
            if (step == 2) {
                if (selectedEntries != readiness.entryEntries().size() + readiness.dependencyEntries().size()
                        || instantiated.size() != 2 || schedules.size() != 2) throw failure("PACK_CALIBRATION_ENTRY_INCOMPLETE");
                nativeEvent(13, server, readiness.entryFunction(), null, executionContext, null, null, null, null, null, null, null, null);
                nativeComplete = true;
            }
        }
        private RuntimeException interrupted() { return new InterruptedRun(original, snapshot()); }
        @Override public void functionInstantiated(Object plain, Object actual, Object source, Object actualControl,
                                                   Object actualParent, List<?> actualEntries, Throwable failure) {
            checkpoint();
            if (step != 2) throw failure("PACK_CALIBRATION_UNEXPECTED_FUNCTION");
            if (plain != readiness.entryFunction() && plain != readiness.dependencyFunction()) throw failure("PACK_CALIBRATION_FUNCTION_CHANGED");
            if (!nativeStarted) {
                if (plain != readiness.entryFunction()) throw failure("PACK_CALIBRATION_FUNCTION_CHANGED");
                actualSource(source);
                nativeEvent(0, server, readiness.entryFunction(), source, null, null, null, null, null, null, null, null, null);
                nativeStarted = true;
            }
            // The native gate checks exact PlainTextFunction.instantiate's returned-this recipe.
            Task trigger = entered.peek();
            if (plain == readiness.dependencyFunction() && (trigger == null || trigger.frame != actualParent
                    || trigger.schedule.function != instantiated.get(readiness.entryFunction()))) throw failure("PACK_CALIBRATION_INSTANTIATION_UNCONFIRMED");
            nativeEvent(14, plain, actual, source, actualControl, actualParent, null, actualEntries,
                    trigger == null ? null : trigger.schedule.provider, trigger == null ? null : trigger.entry,
                    trigger == null ? null : trigger.queueEntry, trigger == null ? null : trigger.action, failure);
            if (failure != null || actual == null || instantiated.put(plain, actual) != null) throw failure("PACK_CALIBRATION_INSTANTIATION_UNCONFIRMED");
            event("instantiated", plain, source, actualControl, null, null, null, actual, failure);
        }
        @Override public void functionCall(Object call, Object function, Object source, Object context, Object parent) {
            checkpoint(); bindContext(context); actualSource(source);
            if (step != 2 || !instantiated.containsValue(function)) throw failure("PACK_CALIBRATION_FUNCTION_CHANGED");
            nativeEvent(1, call, function, source, context, parent, null, null, null, null, null, null, null);
            event("function_call", call, source, context, parent, null, null, function, null);
        }
        @Override public void functionSchedule(Object call, Object function, Object source, Object context, Object parent, Object child,
                                                List<?> actualEntries, Object provider) {
            checkpoint(); bindContext(context); actualSource(source);
            List<?> expected = function == instantiated.get(readiness.entryFunction()) ? readiness.entryEntries()
                    : function == instantiated.get(readiness.dependencyFunction()) ? readiness.dependencyEntries() : null;
            if (step != 2 || expected == null || actualEntries != expected || child == null || provider == null || schedules.size() >= 2)
                throw failure("PACK_CALIBRATION_SCHEDULE_CHANGED");
            for (Schedule previous : schedules) if (previous.call == call && previous.child == child) throw failure("PACK_CALIBRATION_SCHEDULE_CHANGED");
            nativeEvent(2, call, function, source, context, parent, child, actualEntries, provider, null, null, null, null);
            retain(call, function, source, context, parent, child, actualEntries, provider);
            schedules.add(new Schedule(call, function, source, context, parent, child, actualEntries, provider));
            event("function_schedule", call, source, context, child, null, null, provider, null);
        }
        @Override public void beforeTaskCreate(Object provider, Object frame, Object argument) {
            checkpoint(); Schedule schedule = schedule(provider, frame, argument);
            nativeEvent(2, provider, schedule.function, schedule.source, schedule.context, schedule.parent, frame,
                    schedule.entries, provider, argument, null, null, null);
        }
        @Override public void taskCreated(Object provider, Object frame, Object argument, Object queueEntry, Throwable failure) {
            checkpoint(); Schedule schedule = schedule(provider, frame, argument);
            Object action = null;
            if (queueEntry instanceof net.minecraft.commands.execution.CommandQueueEntry<?> actual) {
                if (actual.frame() != frame) throw failure("PACK_CALIBRATION_TASK_CHANGED"); action = actual.action();
            } else if (failure == null) throw failure("PACK_CALIBRATION_TASK_CHANGED");
            nativeEvent(3, provider, schedule.function, schedule.source, schedule.context, schedule.parent, frame,
                    schedule.entries, provider, argument, queueEntry, action, failure);
            event("task_created", provider, schedule.source, schedule.context, frame, argument, queueEntry, action, failure);
            if (failure == null) {
                if (tasks.containsKey(queueEntry)) throw failure("PACK_CALIBRATION_TASK_CHANGED");
                retain(frame, argument, queueEntry, action); tasks.put(queueEntry, new Task(schedule, frame, argument, queueEntry, action));
            }
        }
        @Override public void beforeQueueEntry(Object context, Object queueEntry, Object frame, Object action) {
            checkpoint(); bindContext(context);
            if (step != 2) { event("queue_enter", null, null, context, frame, null, queueEntry, action, null); return; }
            Task task = tasks.get(queueEntry);
            // Auxiliary native queue entries are not selected source entries; their actions receive no captured-proof claim here.
            if (task == null) {
                event("top_queue_enter", null, null, context, frame, null, queueEntry, action, null); return;
            }
            if (task.executed || task.frame != frame || task.action != action) throw failure("PACK_CALIBRATION_TASK_CHANGED");
            nativeEvent(4, context, task.schedule.function, task.schedule.source, context, frame, null, null,
                    task.schedule.provider, task.entry, queueEntry, action, null);
            entered.push(task); event("queue_enter", null, task.schedule.source, context, frame, task.entry, queueEntry, action, null);
        }
        @Override public void afterQueueEntry(Object context, Object queueEntry, Object frame, Object action, Throwable failure) {
            checkpoint(); bindContext(context); Task task = tasks.get(queueEntry);
            if (step != 2 || task == null) { event("queue_exit", null, null, context, frame, null, queueEntry, action, failure); return; }
            if (entered.isEmpty() || entered.peek() != task || task.frame != frame || task.action != action) throw failure("PACK_CALIBRATION_TASK_CHANGED");
            nativeEvent(5, context, task.schedule.function, task.schedule.source, context, frame, null, null,
                    task.schedule.provider, task.entry, queueEntry, action, failure);
            entered.pop(); task.executed = failure == null;
            event("queue_exit", null, task.schedule.source, context, frame, task.entry, queueEntry, action, failure);
        }
        @Override public void beforeEntry(Object entry, Object source, Object context, Object frame) {
            checkpoint(); bindContext(context); actualSource(source);
            if (step != 2 || entered.isEmpty() || entered.peek().entry != entry || entered.peek().frame != frame
                    || entered.peek().schedule.source != source) throw failure("PACK_CALIBRATION_ENTRY_CHANGED");
            Task task = entered.peek();
            nativeEvent(6, entry, task.schedule.function, source, context, frame, null, null, task.schedule.provider, entry,
                    task.queueEntry, task.action, null);
            selectedEntries++; event("entry_begin", entry, source, context, frame, entry, task.queueEntry, task.action, null);
        }
        @Override public void beforeHandler(Object handler, CommandContext<?> context) {
            checkpoint(); actualSource(context.getSource());
            Task task = entered.peek();
            if (step == 2) {
                if (task != null) nativeEvent(7, handler, task.schedule.function, context.getSource(), executionContext, task.frame, null, null,
                        task.schedule.provider, task.entry, task.queueEntry, task.action, null);
            }
            event("handler_enter", handler, context.getSource(), context, task == null ? null : task.frame,
                    task == null ? null : task.entry, task == null ? null : task.queueEntry, null, null);
        }
        @Override public void afterHandler(Object handler, CommandContext<?> context, Integer returned, Throwable failure) {
            checkpoint(); Task task = entered.peek();
            if (step == 2) {
                if (task != null) nativeEvent(8, handler, task.schedule.function, context.getSource(), executionContext, task.frame, null, null,
                        task.schedule.provider, task.entry, task.queueEntry, task.action, failure);
            }
            event("handler_return", handler, context.getSource(), context, task == null ? null : task.frame,
                    task == null ? null : task.entry, task == null ? null : task.queueEntry, null, failure);
        }
        @Override public void queueReturned(Object context, int quota, boolean overflow, int queued, int newTop) {
            synchronized (NativePackCalibrationRun.this) { Accepted actual = accepted.get(original.invocationId()); if (actual != null) actual.queueTerminal = true; }
            checkpoint(); bindContext(context);
            if (step == 2) nativeRawEvent(12, context, null, null, context, null, null, null, null, null, null, null, null,
                    ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).putInt(quota).putInt(overflow ? 1 : 0).putInt(queued).putInt(newTop).array());
            event("queue_terminal", context, null, context, null, null, null, null, null);
            if (queueComplete || quota <= 0 || overflow || queued != 0 || newTop != 0 || !entered.isEmpty()) throw failure("PACK_CALIBRATION_QUEUE_INCOMPLETE");
            queueComplete = true;
        }
        @Override public void beforeCustom(Object receiver, Object chain, Object frame, boolean modifier) {
            checkpoint(); Task task = entered.peek();
            if (step == 2 && task != null) nativeEvent(9, receiver, task.schedule.function, task.schedule.source,
                    executionContext, frame, null, null, task == null ? null : task.schedule.provider, task == null ? null : task.entry,
                    task == null ? null : task.queueEntry, task == null ? null : task.action, null);
            event("custom_enter", receiver, null, chain, frame, null, null, null, null);
        }
        @Override public void afterCustom(Object receiver, Object chain, Object frame, boolean modifier, Throwable failure) {
            checkpoint(); Task task = entered.peek();
            if (step == 2 && task != null) nativeEvent(10, receiver, task.schedule.function, task.schedule.source,
                    executionContext, frame, null, null, task == null ? null : task.schedule.provider, task == null ? null : task.entry,
                    task == null ? null : task.queueEntry, task == null ? null : task.action, failure);
            event("custom_exit", receiver, null, chain, frame, null, null, null, failure);
        }
        @Override public void frameReturned(Object frame, Integer returned) {
            checkpoint();
            if (step == 2) nativeRawEvent(11, frame, null, null, executionContext, frame, null, null, null, null, null, null, null,
                    ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putInt(returned == null ? 0 : returned).putInt(returned == null ? 0 : 1).array());
            event("frame_return", frame, null, executionContext, frame, null, null, null, null);
        }
        private void nativeEvent(int kind, Object owner, Object function, Object source, Object context, Object parent, Object child,
                                 List<?> entries, Object provider, Object entry, Object queueEntry, Object action, Throwable failure) {
            checkpoint();
            // requireRun returns only a checked private native status=1 envelope. A domain-failed raw receipt cannot pass this gate.
            nativeRawEvent(kind, owner, function, source, context, parent, child, entries, provider, entry, queueEntry, action, failure,
                    new byte[0]);
        }
        private void nativeRawEvent(int kind, Object owner, Object function, Object source, Object context, Object parent, Object child,
                                    List<?> entries, Object provider, Object entry, Object queueEntry, Object action, Throwable failure, byte[] facts) {
            checkpoint();
            receipt = readiness.requireRun(original, kind, owner, function, source, context, parent, child, entries,
                    provider, entry, queueEntry, action, failure, facts, control);
            checkpoint();
        }
        private void event(String kind, Object owner, Object source, Object context, Object frame, Object entry, Object queueEntry, Object action, Throwable failure) {
            synchronized (NativePackCalibrationRun.this) {
                if (retainedEventCount >= MAX_EVENTS) throw failure("PACK_CALIBRATION_LIMIT"); retainedEventCount++;
            }
            retain(owner, source, context, frame, entry, queueEntry, action, failure);
            events.add(new Event(kind, events.size(), tick(), owner, source, context, frame, entry, queueEntry, action, failure));
        }
        private void retain(Object... values) {
            for (Object value : values) if (value != null && !references.containsKey(value)) {
                if (references.size() >= 64) throw failure("PACK_CALIBRATION_LIMIT"); references.put(value, Boolean.TRUE);
            }
        }
        private void bindContext(Object context) {
            if (context == null || executionContext != null && executionContext != context) throw failure("PACK_CALIBRATION_CONTEXT_CHANGED");
            executionContext = context;
        }
        private void actualSource(Object source) {
            if (!(source instanceof CommandSourceStack actual) || actual.getServer() != server || actual.getLevel() != level)
                throw failure("PACK_CALIBRATION_OWNER_CHANGED");
        }
        private boolean hasIdentity(List<?> values, Object actual) { for (Object value : values) if (value == actual) return true; return false; }
        private Schedule schedule(Object provider, Object child, Object entry) {
            Schedule selected = null;
            for (Schedule actual : schedules) if (actual.provider == provider && actual.child == child && hasIdentity(actual.entries, entry)) {
                if (selected != null) throw failure("PACK_CALIBRATION_TASK_CHANGED"); selected = actual;
            }
            if (selected == null) throw failure("PACK_CALIBRATION_TASK_CHANGED"); return selected;
        }
    }
    private static final class InterruptedRun extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient Invocation original;
        private final transient List<Event> actualEvents;
        private InterruptedRun(Invocation original, List<Event> actualEvents) { super("PACK run stopped with actual partial observations"); this.original = original; this.actualEvents = actualEvents; }
    }
}
