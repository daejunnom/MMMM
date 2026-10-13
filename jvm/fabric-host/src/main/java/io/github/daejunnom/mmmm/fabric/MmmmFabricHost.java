package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.host.GameThread;
import io.github.daejunnom.mmmm.host.HostAuthority;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.host.PairedLoopbackServer;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.Provider;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.Registrar;
import io.github.daejunnom.mmmm.sdk.RegisteredActionRead;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerChunkEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerEntityEvents;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.minecraft.core.BlockPos;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.permissions.PermissionLevel;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.IdentityHashMap;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

/** Fabric lifecycle and native target access. It does not own project data or a durable operation log. */
public final class MmmmFabricHost implements ModInitializer {
    private static MmmmFabricHost instance;
    private final LoadedChunks loaded = new LoadedChunks();
    private final LoadedEntities entities = new LoadedEntities();
    private final NativeTombstones tombstones = new NativeTombstones(loaded, entities);
    private final ContractJson contracts = new ContractJson();
    private final Map<HostSession, SessionRoute> routes = new IdentityHashMap<>();
    private final List<HostSession> routeOrder = new ArrayList<>();
    private final Map<String, HostSession> invocationRoutes = new HashMap<>();
    private final Map<HostSession, Map<String, Invocation>> nativeHistory = new IdentityHashMap<>();
    private int nativeHistoryCount;
    private long nativeHistoryBytes;
    private Map<String, String> installedSources = Map.of();
    private Set<String> installedActions = Set.of();
    private List<ObjectNode> installedContexts = List.of();
    private final java.util.concurrent.atomic.AtomicInteger pendingInspections = new java.util.concurrent.atomic.AtomicInteger();
    private volatile MinecraftServer server;
    private volatile HostRuntime runtime;
    private volatile HostSession session;
    private volatile PairedLoopbackServer endpoint;
    private volatile boolean reloading;
    private String gameInstanceId;
    private String epoch;
    private String worldId;
    private long registryGeneration;

    public static MmmmFabricHost instance() {
        if (instance == null) throw new ContractException("HOST_NOT_LOADED", "Fabric host has not initialized");
        return instance;
    }

    @Override public void onInitialize() {
        if (instance != null) throw new IllegalStateException("MMMM host initialized twice");
        instance = this;
        new ManualHostConnection(this, contracts).register();
        ServerChunkEvents.CHUNK_LOAD.register((level, chunk, generated) -> loaded.loaded(level, chunk));
        ServerChunkEvents.CHUNK_UNLOAD.register(loaded::unloaded);
        ServerEntityEvents.ENTITY_LOAD.register(entities::loaded);
        ServerEntityEvents.ENTITY_LOAD.register(tombstones::loaded);
        ServerEntityEvents.ENTITY_UNLOAD.register(entities::unloaded);
        ServerLifecycleEvents.SERVER_STARTED.register(current -> {
            server = current;
            reloading = false;
            gameInstanceId = "game-" + UUID.randomUUID();
            worldId = "world-" + UUID.randomUUID();
            newGeneration();
        });
        ServerLifecycleEvents.SERVER_STOPPING.register(current -> disconnect());
        ServerLifecycleEvents.SERVER_STOPPED.register(current -> { disconnect(); tombstones.clear(); loaded.clear(); entities.clear(); reloading = false; server = null; });
        ServerLifecycleEvents.START_DATA_PACK_RELOAD.register((current, resources) -> {
            // The asynchronous reload interval cannot retain an old write grant or target profile.
            if (server == current) { reloading = true; disconnect(); newGeneration(); }
        });
        ServerLifecycleEvents.END_DATA_PACK_RELOAD.register((current, resources, success) -> {
            // Changed registry generations never silently replace bindings or contexts in an existing plan.
            if (server == current) { disconnect(); newGeneration(); reloading = false; }
        });
    }

    private void newGeneration() {
        if (registryGeneration == Long.MAX_VALUE) throw new ContractException("GENERATION_EXHAUSTED", "Host registry generation exhausted");
        registryGeneration++;
        tombstones.clear();
        epoch = "epoch-" + UUID.randomUUID();
    }

    /** Non-secret facts for a trusted launcher/pairing installer. No network listener is started here. */
    public ObjectNode facts() {
        requireServerThread();
        ObjectNode environment = environment();
        ObjectNode facts = ContractJson.newObject().put("gameVersion", version("minecraft"))
                .put("loaderVersion", version("fabricloader")).put("fabricApiVersion", version("fabric-api"))
                .put("javaMajor", Runtime.version().feature()).put("registryGeneration", Long.toString(registryGeneration))
                .put("hostArtifactDigest", artifactDigest(container("mmmm_host")))
                .put("writeProfileEvidence", "not_verified_by_host_startup");
        facts.set("environment", environment);
        facts.putArray("nativeCapabilities").add("mmmm:block_read").add("mmmm:block_patch").add("mmmm:command_execute")
                .add("mmmm:command_complete");
        return facts;
    }

    private ObjectNode hello() {
        requireServerThread();
        ObjectNode result = ContractJson.newObject().put("contractVersion", ContractJson.VERSION)
                .put("hostProtocolVersion", ContractJson.VERSION).put("hostBuild", artifactDigest(container("mmmm_host")))
                .put("gameVersion", version("minecraft")).put("javaMajor", Runtime.version().feature())
                .put("registryDigest", ContractJson.digest(NativeRegistry.observe()));
        result.set("environment", environment());
        result.putObject("loader").put("id", "fabric").put("version", version("fabricloader"));
        result.putArray("capabilities").add("mmmm:block_read").add("mmmm:block_patch").add("mmmm:command_execute")
                .add("mmmm:command_complete").add("mmmm:native_registry");
        contracts.validate("HostHello", result);
        return result;
    }

    <T> CompletionStage<T> gameTask(Supplier<T> action) {
        CompletableFuture<T> future = new CompletableFuture<>(); MinecraftServer current = server;
        if (current == null) return CompletableFuture.failedFuture(new ContractException("HOST_NOT_READY", "The native server is unavailable"));
        try { current.execute(() -> { try { if (future.isDone()) return; if (server != current) throw new ContractException("SESSION_EPOCH_MISMATCH", "The native server generation ended"); future.complete(action.get()); }
            catch (RuntimeException exception) { future.completeExceptionally(exception); } }); }
        catch (RuntimeException exception) { future.completeExceptionally(exception); }
        return future.orTimeout(10, java.util.concurrent.TimeUnit.SECONDS).minimalCompletionStage();
    }
    CompletionStage<Void> gameTask(Runnable action) { return gameTask(() -> { action.run(); return null; }); }
    ServerPlayer pairedCandidate(UUID playerId) { requireServerThread(); return server.getPlayerList().getPlayer(playerId); }
    ObjectNode pairingOffer(UUID playerId, HostSetup setup) {
        requireServerThread(); ServerPlayer player = pairedCandidate(playerId);
        if (player == null || player.createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) {
            throw new ContractException("PERMISSION_DENIED", "Pairing requires a connected actual administrator player");
        }
        if (!setup.hostArtifactDigest().equals(artifactDigest(container("mmmm_host")))) {
            throw new ContractException("HOST_SOURCE_UNAPPROVED", "Loaded host artifact differs from the public approved setup");
        }
        disconnect(); newGeneration();
        ObjectNode offer = ContractJson.newObject().put("kind", "host_pairing_offer").put("protocolVersion", ContractJson.VERSION)
                .put("nonce", "pair-" + UUID.randomUUID()).put("hostArtifactDigest", setup.hostArtifactDigest())
                .put("principalId", "player-" + playerId).put("playerId", playerId.toString())
                .put("dataRoot", setup.dataRoot().toString()).put("projectId", setup.projectId());
        offer.set("hostHello", hello()); offer.set("scope", setup.scope());
        ObjectNode nativeContext = offer.putObject("playerContext").put("dimension", player.level().dimension().identifier().toString())
                .put("executorHandle", "player-" + playerId).put("anchor", "feet");
        nativeContext.putArray("origin").add(player.getX()).add(player.getY()).add(player.getZ());
        nativeContext.putArray("rotationDegrees").add(player.getXRot()).add(player.getYRot());
        var actions = offer.putArray("nativeActions"); nativeActionDescriptors().forEach(actions::add);
        return offer;
    }
    void revokePairing(String installedEpoch) {
        HostSession current = session;
        if (installedEpoch != null && current != null && installedEpoch.equals(current.epoch())) {
            current.close(); PairedLoopbackServer listener = endpoint; if (listener != null) listener.close();
        }
    }

    private record SessionRoute(PairedLoopbackServer endpoint, NativePlanApproval approval,
                                ObjectNode sourceFacts, ObjectNode profileEvidence) { }

    /**
     * Trusted out-of-band composition only. The Rust authority supplies approved artifact/action digests,
     * permissions and immutable contexts after pairing the actual player. There is no RPC install method.
     */
    public String install(UUID pairedPlayer, String principalRef, byte[] asciiBearer,
                          Set<String> permissions, List<ObjectNode> contexts,
                          Map<String, String> approvedSources, Set<String> approvedActions,
                          boolean exactWriteProfileVerified) throws IOException {
        requireServerThread();
        disconnect();
        if (contexts.isEmpty() || contexts.size() > 16) throw new ContractException("CONTEXT_LIMIT", "Pairing requires a bounded nonempty immutable context set");
        if (!"26.3".equals(version("minecraft")) || !"0.19.5".equals(version("fabricloader"))
                || !"0.162.0+26.3".equals(version("fabric-api")) || Runtime.version().feature() != 25) {
            throw new ContractException("TARGET_PROFILE_MISMATCH", "Host activation requires the exact pinned target profile");
        }
        if (server.getPlayerList().getPlayer(pairedPlayer) == null) {
            throw new ContractException("EXECUTOR_DISCONNECTED", "The paired player is not present on this server");
        }
        HostSession candidateSession = new HostSession(principalRef, epoch, gameInstanceId, "server",
                pairedPlayer, permissions, exactWriteProfileVerified);
        contexts.forEach(context -> candidateSession.installContext(contracts, context));
        Map<String, String> admittedBindings = new HashMap<>();
        Set<String> acceptedActions = Set.copyOf(approvedActions);
        Map<String, String> acceptedSources = Map.copyOf(approvedSources);
        ObjectNode installedHello = hello();
        HostAuthority authority = new PlatformAuthority(installedHello);
        HostRuntime candidate = new HostRuntime(contracts, new GameThread() {
            @Override public boolean isSameThread() { return server != null && server.isSameThread(); }
            @Override public void execute(Runnable action) {
                if (server == null) throw new ContractException("HOST_DISCONNECTED", "The server generation has ended");
                server.execute(action);
            }
        }, authority, (binding, descriptor) -> {
            if (descriptor.has("providerId")) {
                String sourceId = descriptor.path("origin").path("sourceId").asText();
                String sourceDigest = descriptor.path("origin").path("sourceDigest").asText();
                if (!sourceDigest.equals(acceptedSources.get(sourceId))) {
                    throw new ContractException("PROVIDER_SOURCE_UNAPPROVED", "Loaded provider artifact is not approved by the pairing authority");
                }
                admittedBindings.put(binding, sourceDigest);
            } else if (!admittedBindings.containsKey(binding)
                    || !admittedBindings.get(binding).equals(descriptor.path("implementationDigest").asText())
                    || !acceptedActions.contains(ContractJson.digest(descriptor))) {
                throw new ContractException("ACTION_UNAPPROVED", "Action contract does not match the pairing authority's approved digest");
            }
        }, Clock.systemUTC());
        try {
            String hostDigest = artifactDigest(container("mmmm_host"));
            String nativeBinding = "binding-" + UUID.randomUUID();
            candidate.registerProvider(provider("mmmm:native", "mmmm_host", version("mmmm_host"), nativeBinding, hostDigest, "builtin"));
            nativeActions(candidate, nativeBinding, hostDigest);
            for (var entry : FabricLoader.getInstance().getEntrypointContainers("mmmm:provider", Provider.class)) {
                ModContainer origin = entry.getProvider();
                String source = origin.getMetadata().getId();
                // Discovery metadata does not authorize loading an entrypoint or registering its actions.
                if (!acceptedSources.containsKey(source)) continue;
                String digest = artifactDigest(origin);
                String binding = "binding-" + UUID.randomUUID();
                candidate.registerProvider(provider(source + ":provider", source, origin.getMetadata().getVersion().getFriendlyString(), binding, digest, "loader_entrypoint"));
                entry.getEntrypoint().register(new Registrar() {
                    @Override public void action(JsonNode descriptor, io.github.daejunnom.mmmm.sdk.ActionHandler handler, OptionalCallbacks callbacks) { candidate.register(binding, descriptor, handler, callbacks); }
                    @Override public void undoAction(String sourceActionId, String undoActionId) { candidate.registerUndo(binding, sourceActionId, undoActionId); }
                });
            }
            runtime = candidate; session = candidateSession;
            HostDispatcher dispatcher = new HostDispatcher(contracts, candidate, this::inspect, Clock.systemUTC());
            endpoint = new PairedLoopbackServer(candidateSession, dispatcher, asciiBearer);
            installedSources = acceptedSources; installedActions = acceptedActions;
            installedContexts = contexts.stream().map(ObjectNode::deepCopy).toList();
            synchronized (routes) { routes.put(candidateSession, new SessionRoute(endpoint, null, null, null)); routeOrder.add(candidateSession); }
            return endpoint.endpoint();
        } catch (IOException | RuntimeException exception) {
            candidate.close(); candidateSession.close(); runtime = null; session = null;
            throw exception;
        }
    }

    /** Candidate descriptors are declarations until the trusted installer admits their digests. */
    public List<ObjectNode> nativeActionDescriptors() {
        requireServerThread();
        String digest = artifactDigest(container("mmmm_host"));
        return descriptors(digest);
    }

    ObjectNode approvalOffer(UUID playerId, HostSetup setup, String planId, String planHash) {
        requireServerThread(); HostSession paired = requireSession(); ServerPlayer player = player(paired);
        if (!playerId.equals(paired.playerId()) || player.createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS
                || !planId.matches("[a-z0-9][a-z0-9._:-]{0,127}") || !planHash.matches("[a-f0-9]{64}")
                || !setup.hostArtifactDigest().equals(artifactDigest(container("mmmm_host")))) {
            throw new ContractException("PERMISSION_DENIED", "Plan approval requires the connected paired administrator and exact local setup");
        }
        synchronized (routes) { if (routes.size() >= 8) throw new ContractException("SESSION_LIMIT", "All retained immutable approval routes remain owned; reconnect before creating another"); }
        if (!installedContexts.getFirst().path("projectId").asText().equals(setup.projectId())) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Public setup project differs from the installed pairing");
        ObjectNode offer = ContractJson.newObject().put("kind", "host_apply_approval_offer").put("protocolVersion", ContractJson.VERSION)
                .put("nonce", "approve-" + UUID.randomUUID()).put("principalId", paired.principalRef()).put("playerId", playerId.toString())
                .put("planId", planId).put("planHash", planHash).put("hostArtifactDigest", setup.hostArtifactDigest());
        offer.set("hostHello", runtime.hello());
        var ids = offer.putArray("contextIds"); installedContexts.forEach(value -> ids.add(value.path("contextId").asText()));
        offer.set("runtimeSourceFacts", NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment()));
        return offer;
    }

    /** Authority-approved new capability route; the runtime, binding IDs and old routes are retained. */
    String installApproval(UUID playerId, ObjectNode offer, ObjectNode authority, byte[] asciiBearer) throws IOException {
        requireServerThread(); HostSession previous = requireSession();
        HostDispatcher.exactFields(authority, Set.of("kind", "protocolVersion", "nonce", "contexts", "approvedSources", "approvedActions", "permissions", "manifest", "profileEvidence"));
        if (!"host_apply_approval_authority".equals(authority.path("kind").asText())
                || !ContractJson.VERSION.equals(authority.path("protocolVersion").asText())
                || !offer.path("nonce").equals(authority.path("nonce")) || !offer.path("hostHello").equals(runtime.hello())
                || !playerId.equals(previous.playerId()) || !previous.principalRef().equals(offer.path("principalId").asText())
                || player(previous).createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw authorityInvalid();
        synchronized (routes) { if (routes.size() >= 8) throw new ContractException("SESSION_LIMIT", "Immutable route retention limit reached"); }
        if (!authority.path("contexts").isArray() || authority.path("contexts").size() != installedContexts.size()) throw authorityInvalid();
        Set<String> matched = new java.util.HashSet<>();
        List<ObjectNode> freshContexts = new ArrayList<>();
        for (JsonNode context : authority.path("contexts")) {
            contracts.validate("ExecutionContext", context); String contextId = context.path("contextId").asText();
            if (!matched.add(contextId) || !sameExecutionIdentity(previous.context(contextId), ContractJson.object(context))) throw authorityInvalid();
            freshContexts.add(ContractJson.object(context).deepCopy());
        }
        if (!authority.path("approvedSources").isObject() || !authority.path("approvedActions").isArray() || !authority.path("permissions").isArray()) throw authorityInvalid();
        Map<String, String> sources = new HashMap<>(); authority.path("approvedSources").fields().forEachRemaining(entry -> {
            if (!entry.getValue().isTextual()) throw authorityInvalid(); sources.put(entry.getKey(), entry.getValue().asText());
        });
        Set<String> actions = new java.util.HashSet<>(); authority.path("approvedActions").forEach(value -> { if (!value.isTextual() || !actions.add(value.asText())) throw authorityInvalid(); });
        if (!installedSources.equals(sources) || !installedActions.equals(actions)) throw new ContractException("DEPENDENCY_CHANGED", "Fresh plan approval cannot replace installed source or action bindings");
        Set<String> permissions = new java.util.HashSet<>();
        Set<String> nativePermissions = Set.of("mmmm:world_read", "mmmm:command_complete", "mmmm:provider_inventory", "mmmm:world_write", "mmmm:command_execute");
        authority.path("permissions").forEach(value -> { if (!value.isTextual() || !nativePermissions.contains(value.asText()) || !permissions.add(value.asText())) throw authorityInvalid(); });
        ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment());
        ObjectNode profileEvidence = ContractJson.object(authority.get("profileEvidence")).deepCopy();
        NativeProfileAdmission.require(contracts, profileEvidence, runtime.hello(), facts, artifactDigest(container("mmmm_host")), Long.toString(registryGeneration));
        if (!NativeProfileAdmission.sourceDigest(facts).equals(NativeProfileAdmission.sourceDigest(ContractJson.object(offer.get("runtimeSourceFacts"))))) {
            throw new ContractException("TARGET_DRIFT", "Observed runtime sources changed while plan approval was pending");
        }
        NativePlanApproval grant = new NativePlanApproval(contracts, authority.get("manifest"), Clock.systemUTC());
        ObjectNode manifest = grant.manifest();
        if (!offer.path("planId").equals(manifest.path("planId")) || !offer.path("planHash").equals(manifest.path("planHash"))
                || !offer.path("principalId").equals(manifest.path("principalId"))
                || !installedContexts.getFirst().path("projectId").equals(manifest.path("projectId"))) throw authorityInvalid();
        HostSession approved = new HostSession(previous.principalRef(), previous.epoch(), previous.gameInstanceId(), previous.side(), playerId, permissions, true);
        freshContexts.forEach(context -> approved.installContext(contracts, context));
        grant.checkSession(approved);
        PairedLoopbackServer listener = null;
        try {
            listener = new PairedLoopbackServer(approved, new HostDispatcher(contracts, runtime, this::inspect, Clock.systemUTC()), asciiBearer);
            synchronized (routes) { routes.put(approved, new SessionRoute(listener, grant, facts.deepCopy(), profileEvidence)); routeOrder.add(approved); }
            session = approved; endpoint = listener; return listener.endpoint();
        } catch (IOException | RuntimeException exception) { if (listener != null) listener.close(); approved.close(); throw exception; }
    }

    void revokeApproval(String installedEndpoint) {
        if (installedEndpoint == null) return;
        synchronized (routes) {
            for (HostSession paired : List.copyOf(routeOrder)) {
                SessionRoute route = routes.get(paired);
                if (route != null && route.approval() != null && installedEndpoint.equals(route.endpoint().endpoint())) {
                    route.endpoint().close(); paired.close(); routes.remove(paired); routeOrder.remove(paired);
                }
            }
            if (session != null && session.closed()) {
                session = routeOrder.isEmpty() ? null : routeOrder.getLast(); endpoint = session == null ? null : routes.get(session).endpoint();
            }
        }
    }
    private static ContractException authorityInvalid() { return new ContractException("HOST_AUTHORITY_INVALID", "Plan authority reply does not match the installed immutable host pairing"); }
    private static boolean sameExecutionIdentity(ObjectNode original, ObjectNode current) {
        ObjectNode before = original.deepCopy(); ObjectNode after = current.deepCopy();
        for (String field : Set.of("policyRevision", "contextDigest")) { before.remove(field); after.remove(field); }
        return ContractJson.digest(before).equals(ContractJson.digest(after));
    }
    private void requireCurrentProfile(SessionRoute route) {
        if (route.profileEvidence() == null || route.sourceFacts() == null) throw new ContractException("TARGET_PROFILE_UNVERIFIED", "A current authority profile receipt is required");
        ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment());
        NativeProfileAdmission.require(contracts, route.profileEvidence(), runtime.hello(), facts, artifactDigest(container("mmmm_host")), Long.toString(registryGeneration));
    }

    /** Consume an authority-issued source proof against the same retained invocation and actual receiver. */
    private void requireActivation(NativeCommandBlockFence.Activation request) {
        requireServerThread(); Invocation invocation = request.invocation();
        HostSession paired = invocationSession(invocation); SessionRoute route = sessionRoute(paired);
        if (route.approval() == null || route.profileEvidence() == null) {
            throw new ContractException("NATIVE_ACTIVATION_UNAPPROVED", "Activation requires an immutable admitted plan and current runtime profile");
        }
        ObjectNode context = invocation.context(); ObjectNode execution = route.approval().execution(invocation);
        if (!ContractJson.digest(context).equals(ContractJson.digest(request.installedContext()))
                || !ContractJson.digest(execution).equals(ContractJson.digest(request.approvedExecution()))
                || !ContractJson.digest(route.approval().manifest()).equals(ContractJson.digest(request.originalPlanManifest()))) {
            throw new ContractException("NATIVE_ACTIVATION_UNAPPROVED", "Activation source cannot be rebound to a different native execution");
        }
        new PlatformAuthority(null).check(paired, context, Set.of("mmmm:world_write", "mmmm:command_execute"), true);
        route.approval().checkInvocation(paired, invocation, true);
        ObjectNode proof = route.approval().activationProof(invocation, request.sealedStep(), request.exactRawSource());
        ObjectNode profile = ContractJson.object(route.profileEvidence().get("profile"));
        if (!Long.toString(registryGeneration).equals(proof.path("registryGeneration").asText())
                || !profile.path("profileId").asText().equals(proof.path("targetProfileId").asText())
                || !ContractJson.digest(profile).equals(proof.path("targetProfileDigest").asText())
                || !profile.path("artifactSha256").asText().equals(proof.path("targetArtifactDigest").asText())) {
            throw new ContractException("TARGET_PROFILE_UNVERIFIED", "Activation source evidence differs from the current installed runtime profile");
        }
        // The approved Rust binary admits producer/source/CAS rights before issuing this private
        // manifest. Their hashes are retained pins, not Java-produced source proof. Java independently
        // checks the real scoped native targets; the executor owns their rolling before/readback SHA.
        for (JsonNode value : proof.path("effectSelectors")) {
            ObjectNode selector = ContractJson.object(value.path("selector"));
            NativeTargets.Observation observed = observeTarget(paired, context, selector, invocation);
            ObjectNode raw = observed.raw(); String kind = selector.path("kind").asText();
            if (!Set.of("score", "storage").contains(kind) || !"known".equals(raw.path("status").asText())
                    || !Set.of("present", "absent").contains(raw.path("presence").asText())
                    || !"full_target".equals(raw.path("coverage").asText())
                    || !selector.equals(raw.get("selector"))
                    || !observed.sha256().equals(ContractJson.sha256(observed.bytes()))) {
                throw new ContractException("NATIVE_BEFORE_INCOMPLETE", "Activation source effect lacks a complete current scoped native observation");
            }
        }
        NativeCommandDispatch.requireIdle(server);
    }

    private void nativeActions(HostRuntime target, String binding, String implementationDigest) {
        for (ObjectNode descriptor : descriptors(implementationDigest)) {
            String id = descriptor.path("actionId").asText();
            target.register(binding, descriptor, (invocation, local) -> {
                local.requireGameThread();
                HostSession paired = invocationSession(invocation);
                ObjectNode context = invocation.context();
                ServerLevel level = level(context.path("dimension").asText());
                ObjectNode input = invocation.arguments();
                ObjectNode output;
                if (id.startsWith("mmmm:authored/")) {
                    SessionRoute route = sessionRoute(paired);
                    if (route.approval() == null) throw new ContractException("PLAN_APPROVAL_REQUIRED", "The native batch has no retained immutable approval");
                    ObjectNode execution = route.approval().execution(invocation);
                    NativeExecutionGuard.CurrentAdmission current = (installedContext, approvedExecution) -> {
                        new PlatformAuthority(null).check(paired, installedContext, Set.of("mmmm:world_write", "mmmm:command_execute"), true);
                        route.approval().checkInvocation(paired, invocation, true);
                        if (!ContractJson.digest(execution).equals(ContractJson.digest(approvedExecution))) {
                            throw new ContractException("NATIVE_EXECUTION_UNAPPROVED", "Native execution differs from its admitted immutable batch");
                        }
                        requireCurrentProfile(route);
                        NativeCommandDispatch.requireIdle(server);
                    };
                    NativeTargets.ResourceAuthority resources = resourceAuthority(route, invocation);
                    NativeCommandBlockFence fence = new NativeCommandBlockFence(server, loaded, invocation,
                            route.approval(), execution, current, this::requireActivation);
                    NativeExecutionGuard guard = new NativeExecutionGuard(contracts, server, player(paired), loaded, entities,
                            invocation, execution, resources, current, fence,
                            parsed -> NativeCommandDispatch.execute(server, parsed), tombstones);
                    ProviderResult result = new NativeSceneExecutor(contracts).execute(server, player(paired), context,
                            invocation, local, execution, guard);
                    return CompletableFuture.completedFuture(result);
                }
                if ("mmmm:command_execute".equals(id)) {
                    NativeCommandDispatch.requireIdle(server);
                    var source = NativeCommands.source(player(paired), level, context);
                    String command = input.path("command").asText();
                    StringReader reader = new StringReader(command);
                    if (command.startsWith("/")) reader.setCursor(1);
                    var parsed = server.getCommands().getDispatcher().parse(reader, source);
                    local.beginMutation();
                    try {
                        int returned = NativeCommandDispatch.execute(server, parsed);
                        output = ContractJson.newObject().put("commandReturnInt32", returned).put("completionClaim", "native_command_return_only");
                    } catch (CommandSyntaxException exception) {
                        return CompletableFuture.completedFuture(ProviderResult.failed(contracts, "COMMAND_FAILED", "unknown"));
                    }
                    return CompletableFuture.completedFuture(ProviderResult.complete(contracts, output, "unknown"));
                }
                String dimension = input.path("dimension").asText();
                if (!dimension.equals(context.path("dimension").asText())) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Action dimension differs from its context");
                BlockPos position = NativeBlocks.position(input.path("position"));
                NativeBlocks.requireScope(context, dimension, position);
                output = NativeBlocks.observe(loaded, level, position);
                if ("mmmm:block_patch".equals(id)) {
                    ObjectNode before = output.deepCopy();
                    var current = loaded.require(level, position).getBlockState(position);
                    var desired = NativeBlocks.decode(input.path("desiredState"));
                    if (current.hasBlockEntity() || desired.hasBlockEntity()) {
                        throw new ContractException("BLOCK_ENTITY_UNSUPPORTED", "This direct-state action does not overwrite block entity data");
                    }
                    if (!before.path("blockState").equals(input.path("expectedState"))) {
                        throw new ContractException("PRECONDITION_CHANGED", "Live block state differs from the pinned before state");
                    }
                    local.beginMutation();
                    boolean changed = level.setBlock(position, desired, 2);
                    ObjectNode after = NativeBlocks.observe(loaded, level, position);
                    ObjectNode evidence = ContractJson.newObject().put("kind", "direct_block_state").put("setBlockReportedSuccess", changed);
                    evidence.set("before", before); evidence.set("after", after); local.recordEffect(evidence);
                    output = evidence.deepCopy().put("indirectEffects", "not_observed");
                    return CompletableFuture.completedFuture(ProviderResult.complete(contracts, output, "recorded"));
                }
                return CompletableFuture.completedFuture(ProviderResult.complete(contracts, output, "none"));
            }, "read".equals(descriptor.path("effect").asText()) ? new OptionalCallbacks(null, null, null, (request, local) -> {
                local.requireGameThread(); ObjectNode context = local.executionContext(); ObjectNode input = request.arguments();
                String dimension = input.path("dimension").asText(); BlockPos position = NativeBlocks.position(input.path("position"));
                if (!dimension.equals(context.path("dimension").asText())) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Read dimension differs from its installed context");
                NativeBlocks.requireScope(context, dimension, position);
                return CompletableFuture.completedFuture(ProviderResult.complete(contracts, NativeBlocks.observe(loaded, level(dimension), position), "none"));
            }) : OptionalCallbacks.none());
        }
    }

    private CompletionStage<ObjectNode> inspect(HostSession paired, ObjectNode context, ObjectNode payload) {
        String kind = HostDispatcher.string(payload, "kind");
        if ("registered_read".equals(kind)) {
            HostDispatcher.exactFields(payload, Set.of("kind", "request"));
            RegisteredActionRead request = new RegisteredActionRead(contracts, payload.get("request"));
            if (!context.path("contextId").asText().equals(request.contextId())) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Registered read context differs from its host envelope");
            return runtime.registeredRead(paired, request, java.time.Instant.now().plusSeconds(10)).thenApply(ProviderResult::wire);
        }
        if ("execution_context".equals(kind)) {
            HostDispatcher.exactFields(payload, Set.of("kind"));
            return CompletableFuture.completedFuture(context.deepCopy());
        }
        if ("dependency".equals(kind)) {
            HostDispatcher.exactFields(payload, Set.of("kind", "bindingId", "actionId", "expectedActionDigest", "expectedImplementationDigest"));
            ObjectNode action = runtime.describe(HostDispatcher.string(payload, "bindingId"), HostDispatcher.string(payload, "actionId"));
            if (!ContractJson.digest(action).equals(payload.path("expectedActionDigest").asText())
                    || !action.path("implementationDigest").asText().equals(payload.path("expectedImplementationDigest").asText())) {
                throw new ContractException("DEPENDENCY_CHANGED", "Pinned registered dependency no longer matches");
            }
            return CompletableFuture.completedFuture(ContractJson.newObject().put("matches", true));
        }
        if (pendingInspections.incrementAndGet() > 32) { pendingInspections.decrementAndGet(); throw new ContractException("INSPECTION_LIMIT", "Native inspection queue is full"); }
        CompletableFuture<ObjectNode> result = new CompletableFuture<>();
        result.whenComplete((value, failure) -> pendingInspections.decrementAndGet());
        try { server.execute(() -> {
            try {
                if (result.isDone()) return;
                Set<String> required = "command_complete".equals(kind) ? Set.of("mmmm:command_complete")
                        : Set.of("undo_registration", "undo_material", "undo_role", "undo_job").contains(kind) ? Set.of("mmmm:provider_inventory") : Set.of("mmmm:world_read");
                new PlatformAuthority(null).check(paired, context, required, false);
                if ("undo_registration".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "bindingId", "sourceActionId"));
                    result.complete(runtime.undoRegistration(HostDispatcher.string(payload, "bindingId"), HostDispatcher.string(payload, "sourceActionId")));
                } else if ("undo_material".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "sourceInvocationId"));
                    result.complete(runtime.undoMaterial(paired, context, HostDispatcher.string(payload, "sourceInvocationId")));
                } else if ("undo_role".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "bindingId", "actionId"));
                    long fromTick = Integer.toUnsignedLong(server.getTickCount());
                    ObjectNode actualFacts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment());
                    String hostArtifact = artifactDigest(container("mmmm_host"));
                    result.complete(runtime.undoRole(HostDispatcher.string(payload, "bindingId"), HostDispatcher.string(payload, "actionId"),
                            registration -> NativeUndoInspection.role(registration, context, actualFacts, hostArtifact,
                                    Long.toString(registryGeneration), fromTick, Integer.toUnsignedLong(server.getTickCount()), java.time.Instant.now())));
                } else if ("undo_job".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "invocationId"));
                    result.complete(runtime.undoJob(paired, context, HostDispatcher.string(payload, "invocationId")));
                } else if ("command_complete".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "request"));
                    JsonNode request = payload.get("request"); contracts.validate("CompleteRequest", request);
                    if (!context.path("contextId").asText().equals(request.path("contextId").asText())) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Completion context differs from its envelope");
                    ServerLevel level = level(context.path("dimension").asText());
                    NativeCommands.complete(server, NativeCommands.source(player(paired), level, context), context,
                            request.path("command").asText(), request.path("cursorUtf16").intValue()).whenComplete((value, failure) -> {
                        if (failure != null) result.completeExceptionally(new ContractException("COMPLETION_FAILED", "Native command completion failed"));
                        else { try { contracts.validate("CommandSuggestions", value); result.complete(value); } catch (RuntimeException exception) { result.completeExceptionally(exception); } }
                    });
                } else if ("world.shape_probe".equals(kind) || "world.shape_query".equals(kind)) {
                    HostDispatcher.exactFields(payload, "world.shape_query".equals(kind) ? Set.of("kind", "query", "expectedProbe") : Set.of("kind", "query"));
                    ObjectNode query = ContractJson.object(payload.get("query")); contracts.validate("ShapeQueryContext", query);
                    if (!context.path("contextId").asText().equals(query.path("contextId").asText())
                            || !context.path("dimension").asText().equals(query.path("dimension").asText())) throw new ContractException("STALE_CONTEXT", "Shape query differs from the actual installed context");
                    ServerLevel level = level(context.path("dimension").asText());
                    boolean queryShape = "world.shape_query".equals(kind);
                    NativeShapes.Observation observation = NativeShapes.observe(loaded, level, context, query, false);
                    ObjectNode probe = shapeProbe(paired, context, level, query, observation);
                    if (queryShape) {
                        ObjectNode expected = ContractJson.object(payload.get("expectedProbe")).deepCopy(); ObjectNode stable = probe.deepCopy();
                        for (String field : Set.of("observedFromTick", "observedToTick", "observedAt")) { expected.remove(field); stable.remove(field); }
                        if (!expected.equals(stable)) throw new ContractException("TARGET_DRIFT", "Shape context differs from its authenticated dependency probe");
                        observation = NativeShapes.observe(loaded, level, context, query, true);
                        probe = shapeProbe(paired, context, level, query, observation);
                    }
                    ObjectNode wrapper = ContractJson.newObject(); wrapper.set("probe", probe);
                    if (queryShape) wrapper.put("observationBytesHex", HexFormat.of().formatHex(ContractJson.bytes(observation.raw())));
                    result.complete(wrapper);
                } else if ("native_registry".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind"));
                    long fromTick = Integer.toUnsignedLong(server.getTickCount());
                    ObjectNode observation = NativeRegistry.observe();
                    byte[] raw = ContractJson.bytes(observation);
                    if (raw.length > 256 * 1024) throw new ContractException("INPUT_LIMIT", "Native registry observation exceeds its raw transport limit");
                    ObjectNode registry = ContractJson.newObject().put("registryDigest", ContractJson.digest(observation)).put("registryGeneration", Long.toString(registryGeneration))
                            .put("observationBytesHex", HexFormat.of().formatHex(raw))
                            .put("observedFromTick", Long.toString(fromTick)).put("observedToTick", Long.toString(Integer.toUnsignedLong(server.getTickCount())))
                            .put("observedAt", java.time.Instant.now().toString()).put("gameVersion", version("minecraft"))
                            .put("locale", player(paired).clientInformation().language()).put("contextDigest", context.path("contextDigest").asText());
                    registry.set("environment", environment()); result.complete(registry);
                } else if ("runtime_sources".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind"));
                    result.complete(NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment()));
                } else if ("target_admission".equals(kind)) {
                    ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment());
                    result.complete(new NativeTargetAdmission(contracts).inspect(server, player(paired), context, facts,
                            artifactDigest(container("mmmm_host")), Long.toString(registryGeneration), payload,
                            (installed, actualFacts, hostDigest, generation, step, index) ->
                                    NativeTargetAdmission.SourceDecision.unsupported("LOADED_DEFINITION_UNAVAILABLE"),
                            (installed, step, index, parsed, admitted) -> {
                                throw new ContractException("NATIVE_READONLY_GUARD_UNAVAILABLE", "No admitted loaded-definition parser closure is installed");
                            }));
                } else if ("calibration_run_source".equals(kind)) {
                    Invocation original = retainedNativeInvocation(paired, context, HostDispatcher.string(payload, "invocationId"));
                    ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment());
                    result.complete(new NativeCalibrationSource(contracts).inspect(context, facts, artifactDigest(container("mmmm_host")),
                            Long.toString(registryGeneration), payload, original, null));
                } else if ("native_targets".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "targets", "sourceInvocationId"));
                    if (!payload.path("targets").isArray() || payload.path("targets").isEmpty() || payload.path("targets").size() > 256) {
                        throw new ContractException("INPUT_LIMIT", "Native target observation requires a bounded exact selector list");
                    }
                    long fromTick = Integer.toUnsignedLong(server.getTickCount());
                    ObjectNode wrapper = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION)
                            .put("contextId", context.path("contextId").asText()).put("contextDigest", context.path("contextDigest").asText())
                            .put("registryGeneration", Long.toString(registryGeneration)).put("observedFromTick", Long.toString(fromTick))
                            .put("observedAt", java.time.Instant.now().toString());
                    Invocation original = null;
                    if (payload.get("sourceInvocationId").isNull()) wrapper.putNull("sourceInvocationId");
                    else {
                        original = retainedNativeInvocation(paired, context, HostDispatcher.string(payload, "sourceInvocationId"));
                        wrapper.put("sourceInvocationId", original.invocationId());
                    }
                    wrapper.set("environment", environment()); var targets = wrapper.putArray("targets");
                    Set<String> selectors = new java.util.HashSet<>();
                    for (JsonNode requested : payload.path("targets")) {
                        ObjectNode selector = ContractJson.object(requested);
                        if (!selectors.add(ContractJson.digest(selector))) throw new ContractException("CONTRACT_INVALID", "Native target selector cannot be repeated");
                        NativeTargets.Observation observation = observeTarget(paired, context, selector, original);
                        ObjectNode target = ContractJson.newObject().put("observationBytesHex", HexFormat.of().formatHex(observation.bytes()))
                                .put("observationSha256", observation.sha256());
                        target.set("selector", selector.deepCopy()); targets.add(target);
                        if (ContractJson.bytes(wrapper).length > 900 * 1024) throw new ContractException("INPUT_LIMIT", "Native target observations exceed the control response byte budget");
                    }
                    wrapper.put("observedToTick", Long.toString(Integer.toUnsignedLong(server.getTickCount()))); result.complete(wrapper);
                } else if ("block_read".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "dimension", "position"));
                    result.complete(readBlock(paired, context, payload.path("dimension").asText(), NativeBlocks.position(payload.path("position"))));
                } else if ("precondition".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "precondition"));
                    JsonNode precondition = payload.get("precondition"); contracts.validate("Precondition", precondition);
                    if (!"region_snapshot".equals(precondition.path("kind").asText())
                            || !Set.of("tracked_changes_only", "full_target").contains(precondition.path("coverage").asText())) {
                        throw new ContractException("PRECONDITION_UNSUPPORTED", "This host generation observes direct block-state targets only");
                    }
                    java.util.regex.Matcher match = java.util.regex.Pattern.compile("^block:([a-z0-9_.-]+:[a-z0-9_./-]+):(-?(?:0|[1-9][0-9]*)):(-?(?:0|[1-9][0-9]*)):(-?(?:0|[1-9][0-9]*))$")
                            .matcher(precondition.path("subject").asText());
                    if (!match.matches()) throw new ContractException("PRECONDITION_UNSUPPORTED", "Precondition target is not a canonical direct block-state subject");
                    BlockPos position = new BlockPos(Integer.parseInt(match.group(2)), Integer.parseInt(match.group(3)), Integer.parseInt(match.group(4)));
                    if ("full_target".equals(precondition.path("coverage").asText())) {
                        String dimension = match.group(1); NativeBlocks.requireScope(context, dimension, position);
                        if (loaded.require(level(dimension), position).getBlockState(position).hasBlockEntity()) {
                            throw new ContractException("PRECONDITION_UNSUPPORTED", "Full direct-state coverage cannot omit a native block entity");
                        }
                    }
                    ObjectNode observed = readBlock(paired, context, match.group(1), position);
                    result.complete(ContractJson.newObject().put("observedDigest", observed.path("snapshotDigest").asText()));
                } else throw new ContractException("INSPECT_UNSUPPORTED", "Inspection selector is not implemented in this host generation");
            } catch (RuntimeException exception) { result.completeExceptionally(exception); }
        }); } catch (RuntimeException exception) { result.completeExceptionally(exception); }
        // Parser futures are observed off the server thread. A stalled native completer has a finite wait.
        return result.orTimeout(10, java.util.concurrent.TimeUnit.SECONDS).minimalCompletionStage();
    }

    private ObjectNode shapeProbe(HostSession paired, ObjectNode context, ServerLevel level, ObjectNode query, NativeShapes.Observation observation) {
        ServerPlayer player = player(paired);
        ObjectNode probe = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION).put("contextDigest", context.path("contextDigest").asText())
                .put("dimension", level.dimension().identifier().toString()).put("gameVersion", version("minecraft"))
                .put("hostBuild", runtime.hello().path("hostBuild").asText()).putNull("artifactSha256")
                .put("registryDigest", runtime.hello().path("registryDigest").asText()).put("registryGeneration", Long.toString(registryGeneration))
                .putNull("targetFingerprint").putNull("serverPackStack").putNull("clientPackStack").putNull("modFingerprintDigest")
                .put("locale", player.clientInformation().language()).put("mode", player.gameMode.getGameModeForPlayer().getName())
                .put("ready", true).put("loaded", observation.loaded()).putNull("entityContextHandle").putNull("entityContextDigest")
                .put("observedFromTick", Long.toString(observation.fromTick())).put("observedToTick", Long.toString(observation.toTick()))
                .put("observedAt", java.time.Instant.now().toString()).putNull("worldRevision").put("dependencyScope", "unknown").putNull("dependencyDigest");
        probe.set("environment", environment());
        BlockPos actualPosition = NativeBlocks.position(query.path("position"));
        probe.putArray("position").add(actualPosition.getX()).add(actualPosition.getY()).add(actualPosition.getZ());
        if (observation.blockState() == null) probe.putNull("blockState"); else probe.set("blockState", observation.blockState().deepCopy());
        if (observation.neighborDigest() == null) probe.putNull("neighborContextDigest"); else probe.put("neighborContextDigest", observation.neighborDigest());
        if (observation.fluidDigest() == null) probe.putNull("fluidContextDigest"); else probe.put("fluidContextDigest", observation.fluidDigest());
        ObjectNode permissions = ContractJson.newObject().put("nativePermission", player.createCommandSourceStack().getPermissionContext().permissionLevel().name());
        permissions.putArray("granted").add(paired.permits("mmmm:world_read") ? "mmmm:world_read" : "none");
        probe.put("permissionDigest", ContractJson.digest(permissions));
        var dependencies = probe.putArray("dependencies");
        for (BlockPos position : observation.dependencies()) {
            ObjectNode dependency = ContractJson.newObject().put("dimension", level.dimension().identifier().toString());
            dependency.putArray("min").add(position.getX()).add(position.getY()).add(position.getZ());
            try { dependency.putArray("maxExclusive").add(Math.addExact(position.getX(), 1)).add(Math.addExact(position.getY(), 1)).add(Math.addExact(position.getZ(), 1)); }
            catch (ArithmeticException exception) { throw new ContractException("UNSUPPORTED", "Native shape dependency cannot be represented as an int32 region"); }
            dependencies.add(dependency);
        }
        return probe;
    }

    private ObjectNode readBlock(HostSession paired, ObjectNode context, String dimension, BlockPos position) {
        if (!dimension.equals(context.path("dimension").asText())) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Readback dimension differs from the installed observation context");
        NativeBlocks.requireScope(context, dimension, position);
        ObjectNode observed = NativeBlocks.observe(loaded, level(dimension), position);
        ObjectNode projection = observed.deepCopy(); projection.remove("observedTick");
        observed.put("snapshotDigest", ContractJson.digest(projection));
        return observed;
    }

    private final class PlatformAuthority implements HostAuthority {
        private final ObjectNode installedFacts;
        private PlatformAuthority(ObjectNode installedFacts) { this.installedFacts = installedFacts; }
        @Override public boolean ready() { return server != null && epoch != null && !reloading; }
        @Override public ObjectNode hello() {
            if (installedFacts == null) throw new ContractException("HELLO_UNAVAILABLE", "Installed platform facts are unavailable");
            return installedFacts.deepCopy();
        }
        @Override public void check(HostSession paired, ObjectNode context, Set<String> permissions, boolean write) {
            requireServerThread(); paired.checkOpen();
            if (!epoch.equals(paired.epoch()) || !gameInstanceId.equals(paired.gameInstanceId())
                    || !worldId.equals(context.path("environment").path("worldId").asText()) || !"server".equals(paired.side())) {
                throw new ContractException("SESSION_EPOCH_MISMATCH", "The actual server generation differs from the paired context");
            }
            if (write) {
                SessionRoute route = sessionRoute(paired);
                if (route.approval() == null) throw new ContractException("PLAN_APPROVAL_REQUIRED", "Native mutation admission requires the retained approved plan");
                // A command source can execute platform overrides. Establish the retained current
                // runtime/source profile before constructing it for a mutation permission check.
                requireCurrentProfile(route);
                NativeCommandDispatch.requireIdle(server);
            }
            ServerPlayer player = player(paired);
            if (!context.path("executorHandle").asText().equals("player-" + paired.playerId())) {
                throw new ContractException("EXECUTOR_SCOPE_MISMATCH", "The installed executor handle does not resolve to the actual paired player");
            }
            if (!player.level().dimension().identifier().toString().equals(context.path("dimension").asText())) {
                throw new ContractException("EXECUTOR_DIMENSION_CHANGED", "The actual paired player is in a different dimension");
            }
            for (String permission : permissions) {
                if (!paired.permits(permission)) throw new ContractException("PERMISSION_DENIED", "The paired capability does not grant this permission");
            }
            if (write && (!paired.verifiedWriteProfile()
                    || player.createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS)) {
                throw new ContractException("PERMISSION_DENIED", "Native writes require an approved exact profile and current server administrator permission");
            }
        }
        @Override public void checkPreconditions(HostSession paired, ObjectNode context, ObjectNode arguments) {
            requireServerThread();
            if (arguments.has("expectedState")) {
                BlockPos position = NativeBlocks.position(arguments.path("position"));
                String dimension = arguments.path("dimension").asText(); NativeBlocks.requireScope(context, dimension, position);
                if (!NativeBlocks.observe(loaded, level(dimension), position).path("blockState").equals(arguments.get("expectedState"))) {
                    throw new ContractException("PRECONDITION_CHANGED", "Target state changed before native apply");
                }
            }
        }
        @Override public void checkInvocation(HostSession paired, Invocation invocation, boolean write) {
            requireServerThread();
            SessionRoute route;
            synchronized (routes) { route = routes.get(paired); }
            if (route == null) throw new ContractException("SESSION_EXPIRED", "The paired route is not retained by this host generation");
            if (write) {
                if (route.approval() == null) throw new ContractException("PLAN_APPROVAL_REQUIRED", "Native writes require a separately approved immutable plan");
                requireCurrentProfile(route);
            }
            if (route.approval() != null) route.approval().checkInvocation(paired, invocation, write);
            String key = invocationRouteKey(invocation);
            HostSession previous = invocationRoutes.putIfAbsent(key, paired);
            if (previous != null && previous != paired) throw new ContractException("SESSION_ROUTE_CHANGED", "An invocation cannot be rebound to a fresh approval route");
            if (invocation.actionId().startsWith("mmmm:authored/")) {
                synchronized (routes) {
                    Map<String, Invocation> retained = nativeHistory.computeIfAbsent(paired, ignored -> new HashMap<>());
                    if (!retained.containsKey(invocation.invocationId())) {
                        int bytes = ContractJson.bytes(invocation.wire()).length;
                        if (nativeHistoryCount >= 512 || nativeHistoryBytes > 32L * 1024 * 1024 - bytes) {
                            throw new ContractException("HOST_HISTORY_FULL", "Original native invocation evidence remains retained; history capacity is exhausted");
                        }
                        retained.put(invocation.invocationId(), invocation); nativeHistoryCount++; nativeHistoryBytes += bytes;
                    }
                }
            }
        }
    }

    private static String invocationRouteKey(Invocation invocation) {
        return invocation.context().path("principalRef").asText() + "|" + invocation.bindingId() + "|" + invocation.invocationId();
    }
    private HostSession invocationSession(Invocation invocation) {
        requireServerThread(); HostSession owner = invocationRoutes.get(invocationRouteKey(invocation));
        if (owner == null) throw new ContractException("PLAN_APPROVAL_REQUIRED", "Invocation has no admitted immutable host route");
        owner.checkOpen(); return owner;
    }
    private SessionRoute sessionRoute(HostSession paired) {
        requireServerThread(); paired.checkOpen();
        synchronized (routes) {
            SessionRoute route = routes.get(paired);
            if (route == null) throw new ContractException("SESSION_EXPIRED", "The native session route is not retained by this host generation");
            return route;
        }
    }
    private NativeTargets.ResourceAuthority resourceAuthority(SessionRoute route, Invocation original) {
        return new NativeTargets.ResourceAuthority() {
            @Override public void require(ObjectNode actualContext, ObjectNode target) {
                if (route.approval() == null || !(original == null ? route.approval().resourceAllowed(actualContext, target)
                        : route.approval().resourceAllowed(original, actualContext, target))) {
                    throw new ContractException("SCOPE_DENIED", "The immutable authority has no exact resource-to-native-target mapping");
                }
            }
            @Override public net.minecraft.world.level.storage.CommandStorage commandStorage(ServerLevel actualLevel) {
                if (actualLevel.getServer() != server) throw new ContractException("SESSION_EPOCH_MISMATCH", "Native storage server changed");
                return server.getCommandStorage();
            }
        };
    }
    private NativeTargets.Observation observeTarget(HostSession paired, ObjectNode context, ObjectNode selector) {
        return observeTarget(paired, context, selector, null);
    }
    private NativeTargets.Observation observeTarget(HostSession paired, ObjectNode context, ObjectNode selector, Invocation original) {
        requireServerThread(); SessionRoute route = sessionRoute(paired);
        return NativeTargets.observe(loaded, entities, level(context.path("dimension").asText()), context, selector,
                resourceAuthority(route, original), (actualLevel, actualContext, exactSelector) -> original == null ? null
                        : tombstones.destroyed(original, actualLevel, actualContext, exactSelector));
    }
    private Invocation retainedNativeInvocation(HostSession paired, ObjectNode context, String id) {
        requireServerThread();
        synchronized (routes) {
            Invocation original = nativeHistory.getOrDefault(paired, Map.of()).get(id);
            if (original == null) {
                for (var entry : nativeHistory.entrySet()) {
                    if (entry.getKey() != paired && entry.getKey().principalRef().equals(paired.principalRef()) && entry.getValue().containsKey(id)) {
                        throw new ContractException("SESSION_ROUTE_CHANGED", "Native history belongs to its retained original session route");
                    }
                }
                throw new ContractException("INVOCATION_UNKNOWN", "Native history is not retained by this paired session");
            }
            if (!original.context().equals(context)) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Native history belongs to another exact original context");
            return original;
        }
    }

    private HostSession requireSession() {
        if (session == null) throw new ContractException("SESSION_EXPIRED", "No paired session is installed");
        session.checkOpen(); return session;
    }
    private ServerPlayer player(HostSession paired) {
        ServerPlayer player = server.getPlayerList().getPlayer(paired.playerId());
        if (player == null) throw new ContractException("EXECUTOR_DISCONNECTED", "The paired player disconnected");
        return player;
    }
    private ServerLevel level(String dimension) {
        for (ServerLevel candidate : server.getAllLevels()) if (candidate.dimension().identifier().toString().equals(dimension)) return candidate;
        throw new ContractException("DIMENSION_UNKNOWN", "Dimension is not loaded on the actual server");
    }
    private ObjectNode environment() {
        return ContractJson.newObject().put("kind", "game").put("gameInstanceId", gameInstanceId).put("sessionEpoch", epoch)
                .put("worldId", worldId).put("side", "server");
    }
    private ObjectNode provider(String providerId, String sourceId, String providerVersion, String binding, String digest, String originKind) {
        ObjectNode result = ContractJson.newObject().put("contractVersion", ContractJson.VERSION).put("providerId", providerId)
                .put("bindingId", binding).put("providerVersion", providerVersion).put("registrationMode", "provider")
                .put("hostProtocolVersion", ContractJson.VERSION).put("compatibilityEvidence", "interface_checked").put("availability", "available");
        result.set("environment", environment());
        result.putObject("origin").put("kind", originKind).put("sourceId", sourceId).put("sourceDigest", digest);
        result.putArray("actions"); return result;
    }
    private List<ObjectNode> descriptors(String digest) {
        ObjectNode point = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        ObjectNode properties = point.putObject("properties");
        properties.putObject("dimension").put("type", "string").put("pattern", "^[a-z0-9_.-]+:[a-z0-9_./-]+$");
        properties.putObject("position").put("type", "array").put("minItems", 3).put("maxItems", 3)
                .putObject("items").put("type", "integer").put("minimum", Integer.MIN_VALUE).put("maximum", Integer.MAX_VALUE);
        point.putArray("required").add("dimension").add("position");
        ObjectNode patch = point.deepCopy();
        ObjectNode blockState = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        blockState.putArray("required").add("blockId").add("properties");
        ObjectNode blockProperties = blockState.putObject("properties");
        blockProperties.putObject("blockId").put("type", "string").put("pattern", "^[a-z0-9_.-]+:[a-z0-9_./-]+$");
        blockProperties.putObject("properties").put("type", "object").putObject("additionalProperties").put("type", "string").put("minLength", 1);
        patch.withObject("properties").set("expectedState", blockState.deepCopy());
        patch.withObject("properties").set("desiredState", blockState.deepCopy());
        patch.withArray("required").add("expectedState").add("desiredState");
        ObjectNode command = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        command.putObject("properties").putObject("command").put("type", "string").put("minLength", 1).put("maxLength", 65_536);
        command.putArray("required").add("command");
        ObjectNode observed = point.deepCopy();
        observed.withObject("properties").set("blockState", blockState.deepCopy());
        observed.withObject("properties").putObject("observedTick").put("type", "string").put("pattern", "^(0|[1-9][0-9]*)$");
        observed.withArray("required").add("blockState").add("observedTick");
        ObjectNode patchOutput = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        ObjectNode patchProperties = patchOutput.putObject("properties");
        patchProperties.putObject("kind").put("const", "direct_block_state");
        patchProperties.putObject("setBlockReportedSuccess").put("type", "boolean");
        patchProperties.putObject("indirectEffects").put("const", "not_observed");
        patchProperties.set("before", observed.deepCopy()); patchProperties.set("after", observed.deepCopy());
        patchOutput.putArray("required").add("kind").add("setBlockReportedSuccess").add("before").add("after").add("indirectEffects");
        ObjectNode commandOutput = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        commandOutput.putObject("properties").putObject("commandReturnInt32").put("type", "integer")
                .put("minimum", Integer.MIN_VALUE).put("maximum", Integer.MAX_VALUE);
        commandOutput.withObject("properties").putObject("completionClaim").put("const", "native_command_return_only");
        commandOutput.putArray("required").add("commandReturnInt32").add("completionClaim");
        List<ObjectNode> result = new ArrayList<>();
        result.add(descriptor("mmmm:block_read", "mmmm:block_state_read", "read", point, observed, digest, "mmmm:world_read", "provider_completion"));
        result.add(descriptor("mmmm:block_patch", "mmmm:block_state_patch", "write", patch, patchOutput, digest, "mmmm:world_write", "independent_readback"));
        result.add(descriptor("mmmm:command_execute", "mmmm:raw_command", "unknown", command, commandOutput, digest, "mmmm:command_execute", "independent_readback"));
        ObjectNode prepared = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        prepared.putArray("required").add("preparedChange");
        prepared.putObject("properties").putObject("preparedChange").put("$ref", "urn:mmmm:contracts:0.2.0#/$defs/ResourceRef");
        Map<String, String> authored = Map.of("instantiate", "prefab_instantiate", "clone", "instance_clone", "relocate", "instance_relocate",
                "display_patch", "display_patch", "command_patch", "command_module_patch", "scene_patch", "scene_import_patch");
        authored.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            ObjectNode action = descriptor("mmmm:authored/" + entry.getKey(), "mmmm:" + entry.getValue(), "write", prepared,
                    NativeSceneExecutor.outputSchema(), digest, "mmmm:world_write", "independent_readback");
            action.put("summary", "Executes the exact authority-sealed native batch; Rust owns preparation and authored commits");
            action.putArray("limitations").add("Native phase execution only; no project, CAS or SQLite commit in Java")
                    .add("Direct native receipts require independent coordinator readback")
                    .add("Unknown loaded membership or incomplete indirect effects remain unverified");
            contracts.validate("ActionDescriptor", action); result.add(action);
        });
        return result;
    }
    private ObjectNode descriptor(String id, String semantic, String effect, ObjectNode input, ObjectNode output, String digest,
                                  String permission, String verification) {
        ObjectNode result = ContractJson.newObject().put("actionId", id).put("contractVersion", ContractJson.VERSION)
                .put("title", id).put("summary", "Native platform action with explicit authenticated context")
                .put("semanticKind", semantic).put("side", "server").put("effect", effect).put("planning", "unsupported")
                .put("completion", "synchronous").put("cancellation", "queued_only").put("recovery", "none")
                .put("idempotency", "read".equals(effect) ? "read" : "coordinator_only").put("verificationRequirement", verification)
                .put("implementationDigest", digest).put("versionEvidence", "interface_checked");
        result.set("inputSchema", input.deepCopy());
        result.set("outputSchema", output.deepCopy());
        result.putArray("requiredContext").add("world").add("dimension").add("executor").add("origin").add("rotation").add("anchor");
        result.putArray("requiredPermissions").add(permission); result.putArray("guarantees").add("authenticated_context").add("server_main_thread");
        result.putArray("limitations").add("Declared interface; actual game verification is recorded separately")
                .add("Direct block-state readback excludes block entity NBT and indirect engine effects")
                .add("Raw command return alone does not prove its effects or completion");
        contracts.validate("ActionDescriptor", result); return result;
    }
    private void requireServerThread() {
        if (server == null || reloading || !server.isSameThread()) throw new ContractException("HOST_NOT_READY", "This operation requires the active ready server thread");
    }
    private void disconnect() {
        synchronized (routes) { routes.forEach((paired, route) -> { route.endpoint().close(); paired.close(); }); routes.clear(); routeOrder.clear(); nativeHistory.clear(); nativeHistoryCount = 0; nativeHistoryBytes = 0; }
        invocationRoutes.clear(); installedSources = Map.of(); installedActions = Set.of(); installedContexts = List.of();
        if (endpoint != null) endpoint.close();
        if (runtime != null) runtime.close();
        if (session != null) session.close();
        endpoint = null; runtime = null; session = null;
    }
    private static ModContainer container(String id) {
        return FabricLoader.getInstance().getModContainer(id).orElseThrow(() -> new ContractException("ARTIFACT_MISSING", "Pinned platform artifact is not loaded"));
    }
    private static String version(String id) { return container(id).getMetadata().getVersion().getFriendlyString(); }
    private static String artifactDigest(ModContainer container) {
        var paths = container.getOrigin().getPaths();
        if (paths.size() != 1 || !Files.isRegularFile(paths.getFirst(), LinkOption.NOFOLLOW_LINKS)) {
            throw new ContractException("ARTIFACT_UNVERIFIED", "Activation requires one bounded installed artifact file");
        }
        try {
            long size = Files.size(paths.getFirst());
            if (size <= 0 || size > 64L * 1024 * 1024) throw new ContractException("ARTIFACT_LIMIT", "Installed provider artifact exceeds its byte limit");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long read = 0;
            try (var input = Files.newInputStream(paths.getFirst())) {
                byte[] buffer = new byte[32 * 1024]; int count;
                while ((count = input.read(buffer)) >= 0) { read += count; if (read > size) throw new ContractException("ARTIFACT_CHANGED", "Loaded artifact changed during observation"); digest.update(buffer, 0, count); }
            }
            if (read != size || Files.size(paths.getFirst()) != size) throw new ContractException("ARTIFACT_CHANGED", "Loaded artifact changed during observation");
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException exception) { throw new ContractException("ARTIFACT_UNVERIFIED", "Loaded artifact could not be observed"); }
        catch (NoSuchAlgorithmException exception) { throw new AssertionError(exception); }
    }
}
