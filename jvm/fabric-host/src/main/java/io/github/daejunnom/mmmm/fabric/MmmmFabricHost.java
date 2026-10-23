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
    private final Map<String, PendingCalibrationOffer> calibrationOffers = new HashMap<>();
    private final Map<String, PendingBootstrapOffer> bootstrapOffers = new HashMap<>();
    // These eight actual attempts survive route retirement, but never a server instance.
    private final Map<String, NativeCalibrationBootstrap.Attempt> bootstrapAttempts = new HashMap<>();
    private final Map<HostSession, String> completedReadonlyPairings = new IdentityHashMap<>();
    private NativeCalibrationApproval.Runner calibrationRunner;
    private int nativeHistoryCount;
    private long nativeHistoryBytes;
    private Map<String, String> installedSources = Map.of();
    private Set<String> installedActions = Set.of();
    private List<ObjectNode> installedContexts = List.of();
    private final java.util.concurrent.atomic.AtomicInteger pendingInspections = new java.util.concurrent.atomic.AtomicInteger();
    private volatile MinecraftServer server;
    private volatile HostRuntime runtime;
    private NativeCompatibilityApprovals compatibilityApprovals;
    private NativeCompatibilityMetadataResolver compatibilityMetadataResolver;
    private volatile HostSession session;
    private volatile PairedLoopbackServer endpoint;
    private volatile boolean reloading;
    private volatile boolean stopping;
    private String gameInstanceId;
    private String epoch;
    private String worldId;
    private long registryGeneration;
    private final NativeDefinitionSlot definitionCollection = new NativeDefinitionSlot();

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
            bootstrapAttempts.clear(); completedReadonlyPairings.clear();
            server = current;
            reloading = false; stopping = false;
            gameInstanceId = "game-" + UUID.randomUUID();
            worldId = "world-" + UUID.randomUUID();
            newGeneration();
        });
        ServerLifecycleEvents.SERVER_STOPPING.register(current -> stopServer(current, false));
        ServerLifecycleEvents.SERVER_STOPPED.register(current -> stopServer(current, true));
        ServerLifecycleEvents.START_DATA_PACK_RELOAD.register((current, resources) -> {
            // The asynchronous reload interval cannot retain an old write grant or target profile.
            if (server == current) { reloading = true; disconnect(); newGeneration(); }
        });
        ServerLifecycleEvents.END_DATA_PACK_RELOAD.register((current, resources, success) -> {
            // Changed registry generations never silently replace bindings or contexts in an existing plan.
            if (server == current) { disconnect(); newGeneration(); reloading = false; }
        });
    }

    private void stopServer(MinecraftServer actual, boolean stopped) {
        if (server != actual) return;
        stopping = true;
        Throwable primary = null;
        // Each attempt receives a fresh lifecycle-only checkpoint. No expired
        // write session or original request callback participates in cleanup.
        for (NativeCalibrationBootstrap.Attempt attempt : List.copyOf(bootstrapAttempts.values())) {
            try {
                attempt.retireRoot(actual, () -> {
                    if (server != actual || !actual.isSameThread()) throw new ContractException("CALIBRATION_ROOT_CLEANUP_OWNER_CHANGED", "The actual server lifecycle cleanup owner changed");
                });
            } catch (RuntimeException | Error failure) {
                if (primary == null) primary = failure; else if (primary != failure) primary.addSuppressed(failure);
            }
        }
        try { disconnect(); }
        catch (RuntimeException | Error failure) {
            if (primary == null) primary = failure; else if (primary != failure) primary.addSuppressed(failure);
        } finally {
            if (stopped) {
                // Native close uncertainty or an unretired root is not deletion
                // or successful close. Its bounded native owner remains until
                // VM retirement, and may keep later root admission unavailable.
                bootstrapAttempts.clear(); tombstones.clear(); loaded.clear(); entities.clear(); reloading = false; server = null;
            }
        }
        if (primary instanceof RuntimeException failure) throw failure;
        if (primary instanceof Error failure) throw failure;
    }

    private void newGeneration() {
        String nextEpoch = "epoch-" + UUID.randomUUID();
        synchronized (definitionCollection) {
            if (registryGeneration == Long.MAX_VALUE) throw new ContractException("GENERATION_EXHAUSTED", "Host registry generation exhausted");
            registryGeneration++; epoch = nextEpoch; definitionCollection.retireAll();
        }
        tombstones.clear();
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
        final HostSession current; final SessionRoute route;
        synchronized (routes) {
            current = session;
            if (installedEpoch == null || current == null || !installedEpoch.equals(current.epoch())) return;
            route = routes.get(current);
            if (route == null) return;
            // 확인한 원래 owner의 route만 분리하며 이후 새 publication은 변경하지 않는다.
            current.close();
            session = null;
            if (endpoint == route.endpoint()) endpoint = null;
        }
        route.endpoint().close();
    }

    private record SessionRoute(PairedLoopbackServer endpoint, NativePlanApproval approval,
                                ObjectNode sourceFacts, ObjectNode profileEvidence, NativeCalibrationApproval calibration,
                                NativeCalibrationBootstrap bootstrap, HostRuntime bootstrapRuntime) { }
    private record PendingCalibrationOffer(HostSession paired, HostRuntime runtime, String offerDigest,
                                           String factsDigest, String hostArtifactDigest, long generation, long until) { }
    private record PendingBootstrapOffer(HostSession paired, HostRuntime runtime, String offerDigest,
                                         String factsDigest, String hostArtifactDigest, long generation, long until) { }

    /**
     * Trusted out-of-band composition only. The Rust authority supplies approved artifact/action digests,
     * permissions and immutable contexts after pairing the actual player. There is no RPC install method.
     */
    public String install(UUID pairedPlayer, String principalRef, byte[] asciiBearer,
                          Set<String> permissions, List<ObjectNode> contexts,
                          Map<String, String> approvedSources, Set<String> approvedActions,
                          boolean exactWriteProfileVerified) throws IOException {
        return install(pairedPlayer, principalRef, asciiBearer, permissions, contexts, approvedSources, approvedActions,
                exactWriteProfileVerified, List.of());
    }

    /** Typed owner records remain distinct from artifact/action approval and from registered providers. */
    public String install(UUID pairedPlayer, String principalRef, byte[] asciiBearer,
                          Set<String> permissions, List<ObjectNode> contexts,
                          Map<String, String> approvedSources, Set<String> approvedActions,
                          boolean exactWriteProfileVerified,
                          List<NativeCompatibilityApprovals.ApprovedProfile> compatibilityProfiles) throws IOException {
        return install(pairedPlayer, principalRef, asciiBearer, permissions, contexts, approvedSources, approvedActions,
                exactWriteProfileVerified, compatibilityProfiles, () -> { });
    }

    /** The private bootstrap passes its original cancellation and monotonic deadline, without renewal. */
    public String install(UUID pairedPlayer, String principalRef, byte[] asciiBearer,
                          Set<String> permissions, List<ObjectNode> contexts,
                          Map<String, String> approvedSources, Set<String> approvedActions,
                          boolean exactWriteProfileVerified,
                          List<NativeCompatibilityApprovals.ApprovedProfile> compatibilityProfiles,
                          Runnable originalControl) throws IOException {
        requireServerThread();
        if (originalControl == null) throw new ContractException("HOST_PAIRING_CANCELLED", "Original pairing control is required");
        long phaseStarted = System.nanoTime();
        Runnable installControl = () -> {
            originalControl.run(); requireServerThread();
            if (System.nanoTime() - phaseStarted >= java.util.concurrent.TimeUnit.SECONDS.toNanos(10)) {
                throw new ContractException("HOST_PAIRING_TIMEOUT", "Metadata installation phase exceeded its original bounded lifetime");
            }
            originalControl.run();
        };
        installControl.run();
        var selectedResolver = new java.util.concurrent.atomic.AtomicReference<NativeCompatibilityMetadataResolver>();
        NativeCompatibilityApprovals pending = new NativeCompatibilityApprovals(contracts, compatibilityProfiles,
                (profile, actualEnvironment, actualGeneration) -> {
                    NativeCompatibilityMetadataResolver resolver = selectedResolver.get();
                    if (resolver == null) throw new ContractException("COMPATIBILITY_SOURCE_UNAVAILABLE", "No current metadata source resolver is installed");
                    resolver.checkApproval(profile, actualEnvironment, actualGeneration);
                });
        try {
            return installNative(pairedPlayer, principalRef, asciiBearer, permissions, contexts, approvedSources, approvedActions,
                    exactWriteProfileVerified, pending, compatibilityProfiles, installControl, selectedResolver);
        } catch (IOException | RuntimeException failure) {
            try { pending.close(); } catch (RuntimeException cleanup) { if (cleanup != failure) failure.addSuppressed(cleanup); }
            NativeCompatibilityMetadataResolver resolver = selectedResolver.get();
            if (resolver != null) try { resolver.close(); } catch (RuntimeException cleanup) { if (cleanup != failure) failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    private String installNative(UUID pairedPlayer, String principalRef, byte[] asciiBearer,
                                 Set<String> permissions, List<ObjectNode> contexts,
                                 Map<String, String> approvedSources, Set<String> approvedActions,
                                 boolean exactWriteProfileVerified, NativeCompatibilityApprovals pendingCompatibility,
                                 List<NativeCompatibilityApprovals.ApprovedProfile> compatibilityProfiles, Runnable installControl,
                                 java.util.concurrent.atomic.AtomicReference<NativeCompatibilityMetadataResolver> selectedResolver) throws IOException {
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
        candidateSession.whenClosed(() -> definitionCollection.retire(candidateSession));
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
            if (binding.startsWith("compat-")) {
                pendingCompatibility.checkRegistration(binding, descriptor); return;
            }
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
        MinecraftServer owningServer = server; long owningGeneration = registryGeneration; String owningEpoch = epoch;
        ObjectNode owningEnvironment = environment();
        List<ObjectNode> metadataContexts = contexts.stream().map(ObjectNode::deepCopy).toList();
        var published = new java.util.concurrent.atomic.AtomicBoolean();
        PairedLoopbackServer listener = null;
        try {
            installControl.run();
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
            Runnable currentMetadataHost = () -> {
                requireServerThread(); candidateSession.checkOpen();
                if (server != owningServer || registryGeneration != owningGeneration || !java.util.Objects.equals(epoch, owningEpoch)
                        || !owningEnvironment.equals(environment())) throw new ContractException("TARGET_DRIFT", "Actual metadata owner generation changed");
                synchronized (routes) {
                    if (published.get() ? runtime != candidate || !routes.containsKey(candidateSession)
                            : runtime != null || session != null || !routes.isEmpty()) {
                        throw new ContractException("SESSION_ROUTE_CHANGED", "Actual metadata runtime owner changed");
                    }
                }
                player(candidateSession);
                for (ObjectNode context : metadataContexts) {
                    if (!candidateSession.context(context.path("contextId").asText()).equals(context)) throw new ContractException("STALE_CONTEXT", "Metadata issuance context changed");
                }
            };
            NativeCompatibilityMetadataResolver resolver = new NativeCompatibilityMetadataResolver(contracts, compatibilityProfiles,
                    owningEnvironment, Long.toString(owningGeneration), version("minecraft"), MmmmFabricHost.class.getClassLoader(),
                    currentMetadataHost, installControl);
            selectedResolver.set(resolver);
            NativeCompatibilityApprovals.MetadataTargetResolver metadataPort = candidateSession.permits("mmmm:provider_inventory") ? resolver
                    : new NativeCompatibilityApprovals.MetadataTargetResolver() {
                        @Override public NativeCompatibilityApprovals.ResolvedMetadataTarget resolve(NativeCompatibilityApprovals.ApprovedProfile profile) {
                            installControl.run(); return null;
                        }
                        @Override public void checkCurrentSources() { resolver.checkCurrentSources(); }
                    };
            resolver.inScope(installControl, () -> {
                pendingCompatibility.registerMetadataBeforeFreeze(candidate, owningEnvironment, Long.toString(owningGeneration), metadataPort);
                return null;
            });
            installControl.run();
            HostDispatcher dispatcher = new HostDispatcher(contracts, candidate, this::inspect, Clock.systemUTC());
            listener = new PairedLoopbackServer(candidateSession, dispatcher, asciiBearer);
            List<ObjectNode> admittedContexts = contexts.stream().map(ObjectNode::deepCopy).toList();
            synchronized (routes) {
                candidateSession.checkOpen();
                routes.put(candidateSession, new SessionRoute(listener, null, null, null, null, null, null)); routeOrder.add(candidateSession);
                installedSources = acceptedSources; installedActions = acceptedActions; installedContexts = admittedContexts;
                compatibilityApprovals = pendingCompatibility;
                compatibilityMetadataResolver = resolver;
                runtime = candidate; session = candidateSession; endpoint = listener;
                published.set(true);
            }
            installControl.run();
            return listener.endpoint();
        } catch (IOException | RuntimeException exception) {
            synchronized (routes) {
                routes.remove(candidateSession); routeOrder.remove(candidateSession);
                if (session == candidateSession) {
                    session = null; if (endpoint == listener) endpoint = null; if (runtime == candidate) runtime = null;
                }
                if (compatibilityApprovals == pendingCompatibility) compatibilityApprovals = null;
                if (compatibilityMetadataResolver == selectedResolver.get()) compatibilityMetadataResolver = null;
            }
            if (listener != null) try { listener.close(); } catch (RuntimeException cleanup) { if (cleanup != exception) exception.addSuppressed(cleanup); }
            try { candidate.close(); } catch (RuntimeException cleanup) { if (cleanup != exception) exception.addSuppressed(cleanup); }
            try { candidateSession.close(); } catch (RuntimeException cleanup) { if (cleanup != exception) exception.addSuppressed(cleanup); }
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
        final HostRuntime currentRuntime;
        synchronized (routes) {
            previous.checkOpen();
            if (session != previous || runtime == null || !routes.containsKey(previous)) throw new ContractException("SESSION_EXPIRED", "Original approval route is no longer installed");
            currentRuntime = runtime;
        }
        HostDispatcher.exactFields(authority, Set.of("kind", "protocolVersion", "nonce", "contexts", "approvedSources", "approvedActions", "permissions", "manifest", "profileEvidence"));
        if (!"host_apply_approval_authority".equals(authority.path("kind").asText())
                || !ContractJson.VERSION.equals(authority.path("protocolVersion").asText())
                || !offer.path("nonce").equals(authority.path("nonce")) || !offer.path("hostHello").equals(currentRuntime.hello())
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
        NativeProfileAdmission.require(contracts, profileEvidence, currentRuntime.hello(), facts, artifactDigest(container("mmmm_host")), Long.toString(registryGeneration));
        if (!NativeProfileAdmission.sourceDigest(facts).equals(NativeProfileAdmission.sourceDigest(ContractJson.object(offer.get("runtimeSourceFacts"))))) {
            throw new ContractException("TARGET_DRIFT", "Observed runtime sources changed while plan approval was pending");
        }
        NativePlanApproval grant = new NativePlanApproval(contracts, authority.get("manifest"), Clock.systemUTC());
        ObjectNode manifest = grant.manifest();
        if (!offer.path("planId").equals(manifest.path("planId")) || !offer.path("planHash").equals(manifest.path("planHash"))
                || !offer.path("principalId").equals(manifest.path("principalId"))
                || !installedContexts.getFirst().path("projectId").equals(manifest.path("projectId"))) throw authorityInvalid();
        HostSession approved = new HostSession(previous.principalRef(), previous.epoch(), previous.gameInstanceId(), previous.side(), playerId, permissions, true);
        approved.whenClosed(() -> definitionCollection.retire(approved));
        freshContexts.forEach(context -> approved.installContext(contracts, context));
        grant.checkSession(approved);
        PairedLoopbackServer listener = null;
        try {
            listener = new PairedLoopbackServer(approved, new HostDispatcher(contracts, currentRuntime, this::inspect, Clock.systemUTC()), asciiBearer);
            synchronized (routes) {
                previous.checkOpen(); approved.checkOpen();
                if (session != previous || runtime != currentRuntime || !routes.containsKey(previous)) throw new ContractException("SESSION_EXPIRED", "Original approval runtime is no longer installed");
                routes.put(approved, new SessionRoute(listener, grant, facts.deepCopy(), profileEvidence, null, null, null)); routeOrder.add(approved);
                session = approved; endpoint = listener;
            }
            return listener.endpoint();
        } catch (IOException | RuntimeException exception) { if (listener != null) listener.close(); approved.close(); throw exception; }
    }

    void revokeApproval(String installedEndpoint) {
        if (installedEndpoint == null) return;
        synchronized (routes) {
            for (HostSession paired : List.copyOf(routeOrder)) {
                SessionRoute route = routes.get(paired);
                if (route != null && (route.approval() != null || route.calibration() != null || route.bootstrap() != null) && installedEndpoint.equals(route.endpoint().endpoint())) {
                    route.endpoint().close(); paired.close(); routes.remove(paired); routeOrder.remove(paired);
                }
            }
            if (session != null && session.closed()) {
                session = routeOrder.isEmpty() ? null : routeOrder.getLast(); endpoint = session == null ? null : routes.get(session).endpoint();
            }
        }
    }
    /** 실제 runner를 만드는 trusted platform composition만 호출한다. RPC/설정/inspect 설치 경로는 없다. */
    void installCalibrationRunner(NativeCalibrationApproval.Runner runner) {
        requireServerThread();
        synchronized (routes) {
            if (calibrationRunner != null || routes.values().stream().anyMatch(route -> route.calibration() != null)) {
                throw new ContractException("CALIBRATION_RUNNER_REBOUND", "설치된 calibration runner 또는 목적 route를 교체할 수 없습니다");
            }
            calibrationRunner = java.util.Objects.requireNonNull(runner);
        }
    }

    ObjectNode calibrationApprovalOffer(UUID playerId, HostSetup setup, String planId, String planHash, Runnable original, long until) {
        original.run(); requireServerThread(); HostSession paired = requireSession(); HostRuntime actualRuntime = runtime;
        long generation = registryGeneration;
        Runnable current = () -> {
            original.run(); requireServerThread(); paired.checkOpen();
            if (until - System.nanoTime() <= 0 || session != paired || runtime != actualRuntime || generation != registryGeneration
                    || !playerId.equals(paired.playerId()) || player(paired).createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw authorityInvalid();
        };
        current.run();
        if (!planId.matches("[a-z0-9][a-z0-9._:-]{0,127}") || !planHash.matches("[a-f0-9]{64}")
                || installedContexts.isEmpty() || !setup.projectId().equals(installedContexts.getFirst().path("projectId").asText())
                || !setup.hostArtifactDigest().equals(artifactDigest(container("mmmm_host")))) throw authorityInvalid();
        ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(generation), environment(), current::run); current.run();
        ObjectNode offer = ContractJson.newObject().put("kind", "host_apply_approval_offer").put("protocolVersion", ContractJson.VERSION)
                .put("nonce", "approve-" + UUID.randomUUID()).put("purpose", NativeCalibrationApproval.PURPOSE)
                .put("dataRoot", setup.dataRoot().toString()).put("projectId", setup.projectId())
                .put("principalId", paired.principalRef()).put("playerId", playerId.toString()).put("planId", planId).put("planHash", planHash)
                .put("hostArtifactDigest", setup.hostArtifactDigest());
        offer.set("hostHello", actualRuntime.hello()); offer.set("runtimeSourceFacts", facts);
        var ids = offer.putArray("contextIds"); installedContexts.forEach(value -> ids.add(value.path("contextId").asText()));
        String nonce = offer.path("nonce").asText();
        try {
            current.run();
            synchronized (routes) {
                calibrationOffers.entrySet().removeIf(entry -> entry.getValue().until() - System.nanoTime() <= 0);
                if (routes.size() >= 8 || calibrationOffers.size() >= 8) throw new ContractException("SESSION_LIMIT", "현재 immutable route 또는 승인 준비 한도가 찼습니다");
                calibrationOffers.put(nonce, new PendingCalibrationOffer(paired, actualRuntime, ContractJson.digest(offer),
                        NativeProfileAdmission.sourceDigest(facts), setup.hostArtifactDigest(), generation, until));
            }
            current.run(); return offer;
        } catch (RuntimeException failure) { releaseCalibrationOffer(nonce); throw failure; }
    }

    void releaseCalibrationOffer(String nonce) { if (nonce != null) synchronized (routes) { calibrationOffers.remove(nonce); } }

    void confirmCalibrationApproval(String address, ObjectNode offer, String selectionDigest, String manifestDigest, Runnable original) {
        original.run(); requireServerThread();
        HostSession paired = null;
        synchronized (routes) {
            for (var entry : routes.entrySet()) if (entry.getValue().calibration() != null && entry.getValue().endpoint().endpoint().equals(address)) {
                paired = entry.getKey(); break;
            }
        }
        if (paired == null) throw authorityInvalid();
        NativeCalibrationApproval grant = sessionRoute(paired).calibration();
        if (!grant.selectionDigest().equals(selectionDigest) || !grant.manifestDigest().equals(manifestDigest)
                || !offer.path("principalId").asText().equals(paired.principalRef())
                || !offer.path("hostHello").equals(runtime.hello())) throw authorityInvalid();
        String contextId = offer.path("contextIds").get(0).asText();
        checkCalibrationCurrent(paired, paired.context(contextId), original, true); original.run();
        grant.activateAfterBridge(paired, selectionDigest, manifestDigest, original); original.run();
    }

    String installCalibrationApproval(UUID playerId, ObjectNode offer, ObjectNode authority, byte[] bearer, Runnable original) throws IOException {
        original.run(); requireServerThread();
        PendingCalibrationOffer pending;
        synchronized (routes) { pending = calibrationOffers.remove(offer.path("nonce").asText()); }
        if (pending == null) throw authorityInvalid();
        HostSession previous = pending.paired();
        Runnable current = () -> {
            original.run(); requireServerThread(); previous.checkOpen();
            synchronized (routes) {
                if (pending.until() - System.nanoTime() <= 0 || session != previous || runtime != pending.runtime()
                        || !routes.containsKey(previous) || registryGeneration != pending.generation()) throw authorityInvalid();
            }
            if (!playerId.equals(previous.playerId()) || !pending.offerDigest().equals(ContractJson.digest(offer))
                    || player(previous).createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw authorityInvalid();
        };
        current.run();
        HostDispatcher.exactFields(authority, Set.of("kind", "protocolVersion", "nonce", "purpose", "contexts", "approvedSources", "approvedActions", "permissions", "manifest"));
        if (!"host_apply_approval_authority".equals(authority.path("kind").asText()) || !ContractJson.VERSION.equals(authority.path("protocolVersion").asText())
                || !offer.path("nonce").equals(authority.path("nonce")) || !NativeCalibrationApproval.PURPOSE.equals(authority.path("purpose").asText())
                || !offer.path("hostHello").equals(pending.runtime().hello()) || !authority.path("contexts").isArray()
                || authority.path("contexts").size() != installedContexts.size()) throw authorityInvalid();
        List<ObjectNode> contexts = new ArrayList<>(); Set<String> ids = new java.util.HashSet<>();
        for (JsonNode value : authority.path("contexts")) {
            current.run(); contracts.validate("ExecutionContext", value); ObjectNode context = ContractJson.object(value); String id = context.path("contextId").asText();
            if (!ids.add(id) || !sameExecutionIdentity(previous.context(id), context)) throw authorityInvalid(); contexts.add(context.deepCopy());
        }
        if (!authority.path("approvedSources").isObject() || !authority.path("approvedActions").isArray() || !authority.path("permissions").isArray()) throw authorityInvalid();
        Map<String, String> sources = new HashMap<>(); authority.path("approvedSources").fields().forEachRemaining(entry -> {
            if (!entry.getValue().isTextual()) throw authorityInvalid(); sources.put(entry.getKey(), entry.getValue().asText());
        });
        Set<String> actions = new java.util.HashSet<>(), permissions = new java.util.HashSet<>();
        authority.path("approvedActions").forEach(value -> { if (!value.isTextual() || !actions.add(value.asText())) throw authorityInvalid(); });
        authority.path("permissions").forEach(value -> { if (!value.isTextual() || !permissions.add(value.asText())) throw authorityInvalid(); });
        if (!sources.equals(installedSources) || !actions.equals(installedActions) || !permissions.equals(NativeCalibrationApproval.READ_PERMISSIONS)) throw authorityInvalid();
        ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment(), current::run); current.run();
        if (!pending.factsDigest().equals(NativeProfileAdmission.sourceDigest(facts))
                || !pending.hostArtifactDigest().equals(artifactDigest(container("mmmm_host")))) throw new ContractException("TARGET_DRIFT", "승인 대기 중 원 runtime source가 바뀌었습니다");
        ObjectNode manifest = ContractJson.object(authority.path("manifest")), inner = ContractJson.object(manifest.path("plan"));
        if (!offer.path("planId").equals(inner.path("planId")) || !offer.path("planHash").equals(inner.path("planHash"))
                || !offer.path("projectId").equals(inner.path("projectId")) || !offer.path("principalId").equals(inner.path("principalId"))
                || !inner.path("steps").isArray() || inner.path("steps").size() != 47
                || !pending.factsDigest().equals(manifest.path("runtimeSourceFactsDigest").asText())
                || !Long.toString(pending.generation()).equals(manifest.path("registryGeneration").asText())) throw authorityInvalid();
        for (JsonNode step : inner.path("steps")) {
            current.run(); ObjectNode descriptor = pending.runtime().describe(step.path("bindingId").asText(), step.path("actionId").asText());
            if (!pending.hostArtifactDigest().equals(step.path("implementationDigest").asText())
                    || !ContractJson.digest(descriptor).equals(step.path("actionDigest").asText())) throw authorityInvalid();
        }
        HostSession approved = new HostSession(previous.principalRef(), previous.epoch(), previous.gameInstanceId(), previous.side(), playerId, permissions, false);
        NativeCalibrationApproval grant;
        try {
            contexts.forEach(context -> approved.installContext(contracts, context));
            NativeCalibrationApproval.Runner actualRunner = calibrationRunner == null
                    ? new NativeCalibrationRunner(contracts, server, approved, () -> player(approved), this::level,
                            new NativeCalibrationRunner.Pins(environment(), NativeProfileAdmission.sourceDigest(facts),
                                    pending.hostArtifactDigest(), Long.toString(pending.generation())))
                    : calibrationRunner;
            grant = new NativeCalibrationApproval(contracts, manifest, approved, Clock.systemUTC(), this::gameTask,
                    this::checkCalibrationCurrent, invocation -> retainAcceptedCalibration(approved, invocation), actualRunner);
            approved.whenClosed(() -> {
                definitionCollection.retire(approved); grant.close();
                if (actualRunner instanceof NativeCalibrationRunner actual) actual.close();
            });
        } catch (RuntimeException failure) { approved.close(); throw failure; }
        PairedLoopbackServer listener = null;
        try {
            current.run();
            listener = new PairedLoopbackServer(approved, new HostDispatcher(contracts, pending.runtime(), this::inspect, Clock.systemUTC(), grant), bearer);
            current.run();
            synchronized (routes) {
                if (routes.size() >= 8) throw new ContractException("SESSION_LIMIT", "현재 immutable route 한도가 찼습니다");
                routes.put(approved, new SessionRoute(listener, null, facts.deepCopy(), null, grant, null, null)); routeOrder.add(approved);
                session = approved; endpoint = listener;
            }
            original.run(); checkCalibrationCurrent(approved, contexts.getFirst(), original, false); return listener.endpoint();
        } catch (IOException | RuntimeException failure) {
            if (listener != null) listener.close(); approved.close();
            synchronized (routes) {
                routes.remove(approved); routeOrder.remove(approved);
                if (session == approved) { session = previous; SessionRoute old = routes.get(previous); endpoint = old == null ? null : old.endpoint(); }
            }
            throw failure;
        }
    }

    private void checkCalibrationCurrent(HostSession paired, ObjectNode context, Runnable original, boolean observeSources) {
        original.run(); requireServerThread(); paired.checkOpen(); SessionRoute route = sessionRoute(paired);
        NativeCalibrationApproval grant = route.calibration();
        if (grant == null || paired.verifiedWriteProfile() || !epoch.equals(paired.epoch())
                || !Long.toString(registryGeneration).equals(grant.registryGeneration()) || !gameInstanceId.equals(paired.gameInstanceId())
                || !context.equals(paired.context(context.path("contextId").asText()))
                || !worldId.equals(context.path("environment").path("worldId").asText()) || !"server".equals(paired.side())) throw authorityInvalid();
        ServerPlayer player = player(paired);
        if (!context.path("executorHandle").asText().equals("player-" + paired.playerId())
                || !player.level().dimension().identifier().toString().equals(context.path("dimension").asText())
                || player.createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw new ContractException("PERMISSION_DENIED", "현재 실제 calibration ADMIN 또는 실행 context 권한이 끝났습니다");
        if (observeSources) {
            ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment(),
                    () -> checkCalibrationCurrent(paired, context, original, false));
            if (!grant.runtimeSourceFactsDigest().equals(NativeProfileAdmission.sourceDigest(facts))
                    || !installedSources.getOrDefault("mmmm_host", "").equals(artifactDigest(container("mmmm_host")))) throw new ContractException("TARGET_DRIFT", "원 calibration source pin이 현재 게임과 다릅니다");
        }
        original.run();
    }

    private void retainAcceptedCalibration(HostSession paired, Invocation invocation) {
        requireServerThread(); if (sessionRoute(paired).calibration() == null) throw authorityInvalid();
        synchronized (routes) {
            Map<String, Invocation> retained = nativeHistory.computeIfAbsent(paired, ignored -> new HashMap<>());
            Invocation previous = retained.get(invocation.invocationId());
            if (previous != null) { if (!previous.wire().equals(invocation.wire())) throw authorityInvalid(); return; }
            int bytes = ContractJson.bytes(invocation.wire()).length;
            if (nativeHistoryCount >= 512 || nativeHistoryBytes > 32L * 1024 * 1024 - bytes) throw new ContractException("HOST_HISTORY_FULL", "원 native Invocation 자료의 보존 한도가 찼습니다");
            String key = invocationRouteKey(invocation); HostSession owner = invocationRoutes.putIfAbsent(key, paired);
            if (owner != null && owner != paired) throw new ContractException("SESSION_ROUTE_CHANGED", "원 Invocation의 route를 바꿀 수 없습니다");
            retained.put(invocation.invocationId(), invocation); nativeHistoryCount++; nativeHistoryBytes += bytes;
        }
    }
    ObjectNode bootstrapApprovalOffer(UUID playerId, HostSetup setup, String planId, String planHash, Runnable original, long until) {
        original.run(); requireServerThread(); HostSession paired = requireSession(); HostRuntime actualRuntime = runtime;
        long generation = registryGeneration;
        Runnable current = () -> {
            original.run(); requireServerThread(); paired.checkOpen();
            if (until - System.nanoTime() <= 0 || session != paired || runtime != actualRuntime || generation != registryGeneration
                    || !playerId.equals(paired.playerId()) || player(paired).createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw authorityInvalid();
        };
        current.run();
        if (!planId.matches("[a-z0-9][a-z0-9._:-]{0,127}") || !planHash.matches("[a-f0-9]{64}")
                || installedContexts.isEmpty() || !setup.projectId().equals(installedContexts.getFirst().path("projectId").asText())
                || !setup.hostArtifactDigest().equals(artifactDigest(container("mmmm_host")))) throw authorityInvalid();
        ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(generation), environment(), current::run); current.run();
        ObjectNode offer = ContractJson.newObject().put("kind", "host_apply_approval_offer").put("protocolVersion", ContractJson.VERSION)
                .put("nonce", "approve-" + UUID.randomUUID()).put("purpose", NativeCalibrationBootstrap.PURPOSE)
                .put("dataRoot", setup.dataRoot().toString()).put("projectId", setup.projectId())
                .put("principalId", paired.principalRef()).put("playerId", playerId.toString()).put("planId", planId).put("planHash", planHash)
                .put("hostArtifactDigest", setup.hostArtifactDigest());
        offer.set("hostHello", actualRuntime.hello()); offer.set("runtimeSourceFacts", facts);
        var ids = offer.putArray("contextIds"); installedContexts.forEach(value -> ids.add(value.path("contextId").asText()));
        String nonce = offer.path("nonce").asText();
        try {
            current.run();
            synchronized (routes) {
                bootstrapOffers.entrySet().removeIf(entry -> entry.getValue().until() - System.nanoTime() <= 0);
                if (routes.size() >= 8 || bootstrapOffers.size() + calibrationOffers.size() >= 8) throw new ContractException("SESSION_LIMIT", "현재 immutable route 또는 승인 준비 한도가 찼습니다");
                bootstrapOffers.put(nonce, new PendingBootstrapOffer(paired, actualRuntime, ContractJson.digest(offer),
                        NativeProfileAdmission.sourceDigest(facts), setup.hostArtifactDigest(), generation, until));
            }
            current.run(); return offer;
        } catch (RuntimeException failure) { releaseBootstrapOffer(nonce); throw failure; }
    }

    void releaseBootstrapOffer(String nonce) { if (nonce != null) synchronized (routes) { bootstrapOffers.remove(nonce); } }

    void confirmBootstrapApproval(String address, ObjectNode offer, String selectionDigest, String manifestDigest, Runnable original) {
        original.run(); requireServerThread(); HostSession paired = null;
        synchronized (routes) {
            for (var entry : routes.entrySet()) if (entry.getValue().bootstrap() != null && entry.getValue().endpoint().endpoint().equals(address)) {
                paired = entry.getKey(); break;
            }
        }
        if (paired == null) throw authorityInvalid();
        NativeCalibrationBootstrap grant = sessionRoute(paired).bootstrap();
        if (!grant.selectionDigest().equals(selectionDigest) || !grant.manifestDigest().equals(manifestDigest)
                || !NativeCalibrationBootstrap.PURPOSE.equals(offer.path("purpose").asText())
                || !offer.path("principalId").asText().equals(paired.principalRef())
                || !offer.path("hostHello").equals(runtime.hello())) throw authorityInvalid();
        String contextId = offer.path("contextIds").get(0).asText();
        checkBootstrapCurrent(paired, paired.context(contextId), original, true); original.run();
        grant.activate(); original.run(); checkBootstrapCurrent(paired, paired.context(contextId), original, true);
    }

    String installBootstrapApproval(UUID playerId, ObjectNode offer, ObjectNode authority, byte[] bearer, Runnable original) throws IOException {
        original.run(); requireServerThread(); PendingBootstrapOffer pending;
        synchronized (routes) { pending = bootstrapOffers.remove(offer.path("nonce").asText()); }
        if (pending == null) throw authorityInvalid(); HostSession previous = pending.paired();
        Runnable current = () -> {
            original.run(); requireServerThread(); previous.checkOpen();
            synchronized (routes) {
                if (pending.until() - System.nanoTime() <= 0 || session != previous || runtime != pending.runtime()
                        || !routes.containsKey(previous) || registryGeneration != pending.generation()) throw authorityInvalid();
            }
            if (!playerId.equals(previous.playerId()) || !pending.offerDigest().equals(ContractJson.digest(offer))
                    || player(previous).createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw authorityInvalid();
        };
        current.run();
        HostDispatcher.exactFields(authority, Set.of("kind", "protocolVersion", "nonce", "purpose", "contexts", "approvedSources", "approvedActions", "permissions", "manifest"));
        if (!"host_apply_approval_authority".equals(authority.path("kind").asText()) || !ContractJson.VERSION.equals(authority.path("protocolVersion").asText())
                || !offer.path("nonce").equals(authority.path("nonce")) || !NativeCalibrationBootstrap.PURPOSE.equals(authority.path("purpose").asText())
                || !offer.path("purpose").equals(authority.path("purpose")) || !offer.path("hostHello").equals(pending.runtime().hello())
                || !authority.path("contexts").isArray() || authority.path("contexts").size() != installedContexts.size()) throw authorityInvalid();
        List<ObjectNode> contexts = new ArrayList<>(); Set<String> ids = new java.util.HashSet<>();
        for (JsonNode value : authority.path("contexts")) {
            current.run(); contracts.validate("ExecutionContext", value); ObjectNode context = ContractJson.object(value); String id = context.path("contextId").asText();
            if (!ids.add(id) || !sameExecutionIdentity(previous.context(id), context)) throw authorityInvalid(); contexts.add(context.deepCopy());
        }
        if (!authority.path("approvedSources").isObject() || !authority.path("approvedActions").isArray() || !authority.path("permissions").isArray()) throw authorityInvalid();
        Map<String, String> sources = new HashMap<>(); authority.path("approvedSources").fields().forEachRemaining(entry -> {
            if (!entry.getValue().isTextual()) throw authorityInvalid(); sources.put(entry.getKey(), entry.getValue().asText());
        });
        Set<String> actions = new java.util.HashSet<>(), permissions = new java.util.HashSet<>();
        authority.path("approvedActions").forEach(value -> { if (!value.isTextual() || !actions.add(value.asText())) throw authorityInvalid(); });
        authority.path("permissions").forEach(value -> { if (!value.isTextual() || !permissions.add(value.asText())) throw authorityInvalid(); });
        if (!sources.equals(installedSources) || !actions.equals(installedActions) || !permissions.equals(NativeCalibrationApproval.READ_PERMISSIONS)) throw authorityInvalid();
        ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment(), current::run); current.run();
        if (!pending.factsDigest().equals(NativeProfileAdmission.sourceDigest(facts))
                || !pending.hostArtifactDigest().equals(artifactDigest(container("mmmm_host")))) throw new ContractException("TARGET_DRIFT", "승인 대기 중 원 bootstrap runtime source가 바뀌었습니다");
        ObjectNode manifest = ContractJson.object(authority.path("manifest")), inner = ContractJson.object(manifest.path("plan"));
        if (!"native_calibration_bootstrap_approval/1".equals(manifest.path("kind").asText())
                || !offer.path("planId").equals(inner.path("planId")) || !offer.path("planHash").equals(inner.path("planHash"))
                || !offer.path("projectId").equals(inner.path("projectId")) || !offer.path("principalId").equals(inner.path("principalId"))
                || !inner.path("steps").isArray() || inner.path("steps").size() != 1
                || !inner.path("nativeExecutions").isArray() || !inner.path("nativeExecutions").isEmpty()
                || !pending.factsDigest().equals(manifest.path("runtimeSourceFactsDigest").asText())
                || !Long.toString(pending.generation()).equals(manifest.path("registryGeneration").asText())) throw authorityInvalid();
        JsonNode step = inner.path("steps").get(0);
        ObjectNode descriptor = pending.runtime().describe(step.path("bindingId").asText(), step.path("actionId").asText());
        if (!NativeCalibrationBootstrap.ACTION_ID.equals(step.path("actionId").asText())
                || !pending.hostArtifactDigest().equals(step.path("implementationDigest").asText())
                || !ContractJson.digest(descriptor).equals(step.path("actionDigest").asText())) throw authorityInvalid();
        HostSession approved = new HostSession(previous.principalRef(), previous.epoch(), previous.gameInstanceId(), previous.side(), playerId, permissions, false);
        NativeCalibrationBootstrap grant;
        try {
            contexts.forEach(context -> approved.installContext(contracts, context));
            grant = new NativeCalibrationBootstrap(contracts, manifest, approved, Clock.systemUTC(), this::gameTask,
                    this::checkBootstrapCurrent, attempt -> retainAcceptedBootstrap(approved, attempt), server, () -> player(approved), this::level);
            approved.whenClosed(() -> { definitionCollection.retire(approved); grant.close(); });
        } catch (RuntimeException failure) { approved.close(); throw failure; }
        PairedLoopbackServer listener = null;
        try {
            current.run();
            listener = new PairedLoopbackServer(approved, new HostDispatcher(contracts, pending.runtime(), this::inspect, Clock.systemUTC(), grant), bearer);
            current.run();
            synchronized (routes) {
                if (routes.size() >= 8) throw new ContractException("SESSION_LIMIT", "현재 immutable route 한도가 찼습니다");
                routes.put(approved, new SessionRoute(listener, null, facts.deepCopy(), null, null, grant, pending.runtime())); routeOrder.add(approved);
                session = approved; endpoint = listener;
            }
            original.run(); checkBootstrapCurrent(approved, contexts.getFirst(), original, true); return listener.endpoint();
        } catch (IOException | RuntimeException failure) {
            if (listener != null) listener.close(); approved.close();
            synchronized (routes) {
                routes.remove(approved); routeOrder.remove(approved);
                if (session == approved) { session = previous; SessionRoute old = routes.get(previous); endpoint = old == null ? null : old.endpoint(); }
            }
            throw failure;
        }
    }

    private void checkBootstrapCurrent(HostSession paired, ObjectNode context, Runnable original, boolean observeSources) {
        original.run(); requireServerThread(); paired.checkOpen(); SessionRoute route = sessionRoute(paired);
        NativeCalibrationBootstrap grant = route.bootstrap();
        if (grant == null || runtime != route.bootstrapRuntime() || paired.verifiedWriteProfile() || !epoch.equals(paired.epoch())
                || !Long.toString(registryGeneration).equals(grant.registryGeneration()) || !gameInstanceId.equals(paired.gameInstanceId())
                || !context.equals(paired.context(context.path("contextId").asText()))
                || !worldId.equals(context.path("environment").path("worldId").asText()) || !"server".equals(paired.side())) throw authorityInvalid();
        ServerPlayer player = player(paired);
        if (!context.path("executorHandle").asText().equals("player-" + paired.playerId())
                || !player.level().dimension().identifier().toString().equals(context.path("dimension").asText())
                || player.createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw new ContractException("PERMISSION_DENIED", "현재 실제 bootstrap ADMIN 또는 실행 context 권한이 끝났습니다");
        if (observeSources) {
            ObjectNode facts = NativeSourceFacts.observe(server, Long.toString(registryGeneration), environment(),
                    () -> checkBootstrapCurrent(paired, context, original, false));
            if (sessionRoute(paired) != route || runtime != route.bootstrapRuntime()
                    || !grant.runtimeSourceFactsDigest().equals(NativeProfileAdmission.sourceDigest(facts))
                    || !installedSources.getOrDefault("mmmm_host", "").equals(artifactDigest(container("mmmm_host")))) throw new ContractException("TARGET_DRIFT", "원 bootstrap source pin이 현재 게임과 다릅니다");
        }
        original.run();
    }

    private void retainAcceptedBootstrap(HostSession paired, NativeCalibrationBootstrap.Attempt attempt) {
        requireServerThread(); if (sessionRoute(paired).bootstrap() == null) throw authorityInvalid();
        Invocation invocation = attempt.original(); attempt.requireActualOwner(server, gameInstanceId, worldId);
        synchronized (routes) {
            NativeCalibrationBootstrap.Attempt previousAttempt = bootstrapAttempts.get(invocation.invocationId());
            if (previousAttempt != null) {
                if (previousAttempt != attempt) throw authorityInvalid(); return;
            }
            // Reject before the first effect. Unresolved history is never evicted to make room.
            if (bootstrapAttempts.size() >= 8) throw new ContractException("CALIBRATION_BOOTSTRAP_HISTORY_FULL", "The bounded actual bootstrap history is full");
            Map<String, Invocation> retained = nativeHistory.computeIfAbsent(paired, ignored -> new HashMap<>());
            Invocation previous = retained.get(invocation.invocationId());
            if (previous != null) { if (!previous.wire().equals(invocation.wire())) throw authorityInvalid(); return; }
            int bytes = ContractJson.bytes(invocation.wire()).length;
            if (nativeHistoryCount >= 512 || nativeHistoryBytes > 32L * 1024 * 1024 - bytes) throw new ContractException("HOST_HISTORY_FULL", "원 native Invocation 자료의 보존 한도가 찼습니다");
            String key = invocationRouteKey(invocation); HostSession owner = invocationRoutes.putIfAbsent(key, paired);
            if (owner != null && owner != paired) throw new ContractException("SESSION_ROUTE_CHANGED", "원 Invocation의 route를 바꿀 수 없습니다");
            retained.put(invocation.invocationId(), invocation); nativeHistoryCount++; nativeHistoryBytes += bytes;
            bootstrapAttempts.put(invocation.invocationId(), attempt);
        }
    }

    /** Called only after the ordinary private bridge has consumed and checked its actual completion reply. */
    void confirmReadonlyPairing(UUID playerId, String expectedEpoch, ObjectNode completed, Runnable original) {
        original.run(); requireServerThread(); HostSession actual = requireSession(); SessionRoute route = sessionRoute(actual);
        if (!playerId.equals(actual.playerId()) || !expectedEpoch.equals(epoch) || !expectedEpoch.equals(actual.epoch())
                || !expectedEpoch.equals(completed.path("hostEpoch").asText()) || !completed.path("ready").isBoolean()
                || !completed.path("ready").booleanValue() || !ContractJson.VERSION.equals(completed.path("protocolVersion").asText())
                || !actual.context(completed.path("contextId").asText()).path("contextId").equals(completed.path("contextId"))
                || route.bootstrap() != null || route.calibration() != null || route.approval() != null
                || player(actual).createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw authorityInvalid();
        original.run(); completedReadonlyPairings.put(actual, completed.path("contextId").asText()); original.run();
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
                if ("mmmm:calibration_command_execute".equals(id)) {
                    throw new ContractException("CALIBRATION_PRIVATE_ROUTE_REQUIRED", "Only the exact private normative calibration purpose can execute this action");
                }
                if (NativeCalibrationBootstrap.ACTION_ID.equals(id)) {
                    throw new ContractException("CALIBRATION_BOOTSTRAP_PRIVATE_ROUTE_REQUIRED", "Only the exact private calibration bootstrap purpose can execute this action");
                }
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
                if ("mmmm:block_patch".equals(id)) {
                    SessionRoute directRoute = sessionRoute(paired);
                    ObjectNode preflight = ownedBlockPreflight(paired, context, input, implementationDigest, local::checkActive, invocation);
                    if (!"known".equals(preflight.path("status").asText())) throw new ContractException(preflight.path("reasonCode").asText(), "Owned direct block conditions are unsupported");
                    ObjectNode before = ContractJson.newObject().put("dimension", dimension).put("observedTick", preflight.path("observedToTick").asText());
                    before.set("position", preflight.path("position").deepCopy()); before.set("blockState", preflight.path("cells").get(13).path("state").deepCopy());
                    var desired = OwnedBlockPatchPreflight.desired(input.path("desiredState"));
                    local.beginMutation();
                    Runnable directCurrent = () -> {
                        local.checkActive();
                        if (runtime != target || sessionRoute(paired) != directRoute) throw new ContractException("SESSION_ROUTE_CHANGED", "Direct mutation route changed during admission");
                        new PlatformAuthority(null).check(paired, context, Set.of("mmmm:world_write"), false); local.checkActive();
                    };
                    OwnedBlockPatchPreflight.requireCurrentCells(loaded, level, context, input, Long.toString(registryGeneration), directCurrent);
                    boolean changed = level.setBlock(position, desired, 2);
                    ObjectNode after = NativeBlocks.observe(loaded, level, position);
                    ObjectNode evidence = ContractJson.newObject().put("kind", "direct_block_state").put("setBlockReportedSuccess", changed);
                    evidence.put("knownProducerId", OwnedBlockPatchPreflight.PRODUCER).put("preflightPin", preflight.path("conditionsDigest").asText());
                    OwnedBlockPatchPreflight.directFields(evidence);
                    evidence.set("before", before); evidence.set("after", after); local.recordEffect(evidence);
                    output = evidence.deepCopy();
                    return CompletableFuture.completedFuture(ProviderResult.complete(contracts, output, "recorded"));
                }
                output = NativeBlocks.observe(loaded, level, position);
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

    private CompletionStage<ObjectNode> inspect(HostSession paired, ObjectNode context, ObjectNode payload, HostDispatcher.InspectionControl control) {
        control.checkpoint();
        String kind = HostDispatcher.string(payload, "kind");
        if ("registered_read".equals(kind)) {
            HostDispatcher.exactFields(payload, Set.of("kind", "request"));
            RegisteredActionRead request = new RegisteredActionRead(contracts, payload.get("request"));
            if (!context.path("contextId").asText().equals(request.contextId())) throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Registered read context differs from its host envelope");
            return runtime.registeredRead(paired, request, control.deadlineAt()).thenApply(ProviderResult::wire);
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
        control.whenStopped(() -> result.cancel(false));
        try { server.execute(() -> {
            try {
                if (result.isDone()) return;
                control.checkpoint();
                Set<String> required = "command_complete".equals(kind) ? Set.of("mmmm:command_complete")
                        : Set.of("undo_registration", "undo_material", "undo_role", "undo_job", "compatibility_interface").contains(kind) ? Set.of("mmmm:provider_inventory") : Set.of("mmmm:world_read");
                new PlatformAuthority(null).check(paired, context, required, false);
                if ("compatibility_interface".equals(kind)) {
                    result.complete(inspectCompatibility(paired, context, payload, control, result));
                } else if ("undo_registration".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "bindingId", "sourceActionId"));
                    result.complete(runtime.undoRegistration(HostDispatcher.string(payload, "bindingId"), HostDispatcher.string(payload, "sourceActionId")));
                } else if ("undo_material".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "sourceInvocationId"));
                    result.complete(runtime.undoMaterial(paired, context, HostDispatcher.string(payload, "sourceInvocationId")));
                } else if ("undo_role".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "bindingId", "actionId"));
                    long fromTick = Integer.toUnsignedLong(server.getTickCount());
                    ObjectNode actualFacts = collectSourceFacts(paired, context, control, result, required);
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
                    ObjectNode observation = collectRegistryDefinitions(paired, context, control, result);
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
                    result.complete(collectSourceFacts(paired, context, control, result, required));
                } else if ("owned_block_patch_preflight".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "dimension", "position", "expectedState", "desiredState", "expectedRegistryGeneration"));
                    ObjectNode input = payload.deepCopy(); input.remove("kind");
                    result.complete(ownedBlockPreflight(paired, context, input, nativeBlockImplementation(), () -> {
                        control.checkpoint();
                        if (result.isDone()) throw new ContractException("CANCELLATION_REQUESTED", "Owned block inspection ended");
                    }, null));
                } else if ("target_admission".equals(kind)) {
                    ObjectNode facts = collectSourceFacts(paired, context, control, result, required);
                    result.complete(new NativeTargetAdmission(contracts).inspect(server, player(paired), context, facts,
                            artifactDigest(container("mmmm_host")), Long.toString(registryGeneration), payload,
                            (installed, actualFacts, hostDigest, generation, step, index) ->
                                    NativeTargetAdmission.SourceDecision.unsupported(definitionAdmissionReason(paired, context)),
                            (installed, step, index, parsed, admitted) -> {
                                throw new ContractException("NATIVE_READONLY_GUARD_UNAVAILABLE", "No admitted loaded-definition parser closure is installed");
                            }));
                } else if ("calibration_bootstrap_successor".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "invocationId", "invocationDigest", "sourceBundleDigest", "frozenManifestDigest"));
                    NativeCalibrationBootstrap.Attempt attempt = bootstrapAttempts.get(HostDispatcher.string(payload, "invocationId"));
                    if (attempt == null || !attempt.invocationDigest().equals(HostDispatcher.string(payload, "invocationDigest"))
                            || !attempt.sourceBundleDigest().equals(HostDispatcher.string(payload, "sourceBundleDigest"))
                            || !attempt.frozenManifestDigest().equals(HostDispatcher.string(payload, "frozenManifestDigest"))) throw authorityInvalid();
                    SessionRoute originalRoute = sessionRoute(paired); MinecraftServer originalServer = server;
                    HostRuntime originalRuntime = runtime; long originalGeneration = registryGeneration;
                    Runnable current = () -> {
                        control.checkpoint(); requireServerThread(); paired.checkOpen();
                        if (result.isDone() || sessionRoute(paired) != originalRoute || server != originalServer || runtime != originalRuntime
                                || registryGeneration != originalGeneration || !context.path("contextId").asText().equals(completedReadonlyPairings.get(paired))
                                || !context.equals(paired.context(context.path("contextId").asText()))) throw authorityInvalid();
                        attempt.requireActualOwner(server, gameInstanceId, worldId);
                        ObjectNode before = attempt.original().context();
                        if (!paired.principalRef().equals(before.path("principalRef").asText())
                                || !paired.principalRef().equals(context.path("principalRef").asText())
                                || !before.path("projectId").equals(context.path("projectId"))
                                || !before.path("dimension").equals(context.path("dimension"))
                                || player(paired).createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) throw authorityInvalid();
                        new PlatformAuthority(null).check(paired, context, Set.of("mmmm:world_read"), false);
                        attempt.requireScope(context);
                        control.checkpoint();
                    };
                    result.complete(NativeCalibrationFunctions.checked(() -> {
                        current.run();
                        return attempt.observeSuccessor(server, level(context.path("dimension").asText()), paired, context, current);
                    }, current));
                } else if ("calibration_bootstrap_target_state".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "sourceBundleDigest"));
                    NativeCalibrationBootstrap bootstrap = sessionRoute(paired).bootstrap();
                    if (bootstrap == null) throw new ContractException("CALIBRATION_BOOTSTRAP_APPROVAL_PENDING", "No original private bootstrap approval owns this query");
                    Runnable current = () -> {
                        control.checkpoint();
                        if (result.isDone()) throw new ContractException("CANCELLATION_REQUESTED", "Bootstrap inspection ended");
                        checkBootstrapCurrent(paired, context, control::checkpoint, true);
                    };
                    result.complete(NativeCalibrationFunctions.checked(() -> bootstrap.observeState(paired, context,
                            HostDispatcher.string(payload, "sourceBundleDigest"), control), current));
                } else if ("calibration_target_state".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "caseId", "functionId", "targetBindings"));
                    SessionRoute originalRoute = sessionRoute(paired);
                    MinecraftServer originalServer = server; HostRuntime originalRuntime = runtime; long originalGeneration = registryGeneration;
                    Runnable current = () -> {
                        control.checkpoint(); requireServerThread(); paired.checkOpen();
                        if (result.isDone() || sessionRoute(paired) != originalRoute || server != originalServer || runtime != originalRuntime
                                || registryGeneration != originalGeneration
                                || !context.equals(paired.context(context.path("contextId").asText()))) throw authorityInvalid();
                        new PlatformAuthority(null).check(paired, context, Set.of("mmmm:world_read"), false); control.checkpoint();
                    };
                    result.complete(NativeCalibrationFunctions.checked(() -> {
                        var selected = NativeCalibrationTargetImages.select(HostDispatcher.string(payload, "caseId"),
                                HostDispatcher.string(payload, "functionId"), payload.get("targetBindings"));
                        ObjectNode facts = collectSourceFacts(paired, context, control, result, required);
                        String generation = Long.toString(registryGeneration);
                        String factsDigest = NativeProfileAdmission.sourceDigest(facts), hostDigest = artifactDigest(container("mmmm_host"));
                        var images = NativeCalibrationTargetImages.observeSelected(server, level(context.path("dimension").asText()),
                                paired, context, selected, current::run);
                        ObjectNode after = collectSourceFacts(paired, context, control, result, required);
                        if (!factsDigest.equals(NativeProfileAdmission.sourceDigest(after))
                                || !hostDigest.equals(artifactDigest(container("mmmm_host")))) throw new ContractException("TARGET_DRIFT", "The actual read-only source changed during target capture");
                        return NativeCalibrationRunFacts.fullImages(new NativeCalibrationRunner.Pins(environment(),
                                factsDigest, hostDigest, generation), context, images);
                    }, current));
                } else if ("calibration_state".equals(kind)) {
                    HostDispatcher.exactFields(payload, Set.of("kind", "invocationId", "invocationDigest"));
                    Invocation originalInvocation = retainedNativeInvocation(paired, context, HostDispatcher.string(payload, "invocationId"));
                    if (!ContractJson.digest(originalInvocation.wire()).equals(HostDispatcher.string(payload, "invocationDigest"))) throw authorityInvalid();
                    NativeCalibrationApproval calibration = sessionRoute(paired).calibration();
                    if (calibration == null) throw new ContractException("CALIBRATION_APPROVAL_PENDING", "No original private calibration approval owns this query");
                    Runnable current = () -> checkCalibrationCurrent(paired, context, control::checkpoint, true);
                    result.complete(NativeCalibrationFunctions.checked(() -> {
                        var images = calibration.observeState(paired, context, HostDispatcher.string(payload, "invocationId"),
                                HostDispatcher.string(payload, "invocationDigest"), control,
                                (original, program, entered) -> NativeCalibrationTargetImages.observe(server,
                                        level(context.path("dimension").asText()), paired, context, program, entered));
                        return NativeCalibrationRunFacts.fullImages(new NativeCalibrationRunner.Pins(environment(),
                                calibration.runtimeSourceFactsDigest(), artifactDigest(container("mmmm_host")), Long.toString(registryGeneration)), context, images);
                    }, current));
                } else if ("calibration_run_source".equals(kind)) {
                    Invocation original = retainedNativeInvocation(paired, context, HostDispatcher.string(payload, "invocationId"));
                    ObjectNode facts = collectSourceFacts(paired, context, control, result, required);
                    NativeCalibrationApproval calibration = sessionRoute(paired).calibration();
                    result.complete(NativeCalibrationFunctions.checked(() -> new NativeCalibrationSource(contracts).inspect(context, facts, artifactDigest(container("mmmm_host")),
                            Long.toString(registryGeneration), payload, original, calibration == null ? null
                                    : (installed, id) -> calibration.lookup(paired, installed, id, control),
                            () -> checkCalibrationCurrent(paired, context, control::checkpoint, false)),
                            () -> checkCalibrationCurrent(paired, context, control::checkpoint, true)));
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
        try { result.orTimeout(Math.min(10_000, control.remainingMillis()), java.util.concurrent.TimeUnit.MILLISECONDS); }
        catch (RuntimeException failure) { result.completeExceptionally(failure); }
        return result.minimalCompletionStage();
    }

    /** Source-input and public class metadata cannot make an executable compatibility provider. */
    private ObjectNode inspectCompatibility(HostSession paired, ObjectNode context, ObjectNode payload,
                                           HostDispatcher.InspectionControl control, CompletableFuture<ObjectNode> response) {
        MinecraftServer currentServer = server; HostRuntime currentRuntime = runtime; long generation = registryGeneration;
        String currentEpoch = epoch; SessionRoute route = sessionRoute(paired); NativeCompatibilityApprovals retained = compatibilityApprovals;
        NativeCompatibilityMetadataResolver resolver = compatibilityMetadataResolver;
        Runnable checkpoint = () -> {
            control.checkpoint(); requireServerThread(); paired.checkOpen();
            if (response.isDone()) throw new ContractException("CANCELLATION_REQUESTED", "Compatibility inspection ended");
            if (server != currentServer || runtime != currentRuntime || registryGeneration != generation
                    || !java.util.Objects.equals(epoch, currentEpoch) || sessionRoute(paired) != route || compatibilityApprovals != retained
                    || compatibilityMetadataResolver != resolver) {
                throw new ContractException("SESSION_EPOCH_MISMATCH", "Compatibility inspection owner or generation changed");
            }
            if (!paired.context(HostDispatcher.string(context, "contextId")).equals(context)) throw new ContractException("STALE_CONTEXT", "Compatibility context differs from its current owner");
            new PlatformAuthority(null).check(paired, context, Set.of("mmmm:provider_inventory"), false); control.checkpoint();
        };
        try {
            checkpoint.run();
            HostDispatcher.exactFields(payload, Set.of("kind", "approvedProfileRef", "profileDigest"));
            if (retained == null || resolver == null) throw new ContractException("COMPATIBILITY_SOURCE_UNAVAILABLE", "No current compatibility metadata resolver is installed");
            ObjectNode observed = resolver.inScope(checkpoint,
                    () -> retained.inspect(currentRuntime, environment(), Long.toString(generation), payload));
            checkpoint.run(); return observed;
        } catch (RuntimeException failure) {
            try { checkpoint.run(); } catch (RuntimeException current) { if (current != failure) failure.addSuppressed(current); }
            throw failure;
        }
    }

    /** The built-in registration is checked as a whole; an action name or caller digest is no grant. */
    private String nativeBlockImplementation() {
        String found = null;
        for (JsonNode provider : runtime.inventory().path("providers")) {
            if (!"mmmm:native".equals(provider.path("providerId").asText())
                    || !"builtin".equals(provider.path("origin").path("kind").asText())
                    || !"mmmm_host".equals(provider.path("origin").path("sourceId").asText())) continue;
            String digest = provider.path("origin").path("sourceDigest").asText();
            if (!digest.equals(installedSources.get("mmmm_host"))) throw new ContractException("OWNED_BLOCK_SOURCE_UNAVAILABLE", "Built-in source approval changed");
            ObjectNode expected = descriptors(digest).stream().filter(action -> "mmmm:block_patch".equals(action.path("actionId").asText())).findFirst().orElseThrow();
            ObjectNode actual = runtime.describe(provider.path("bindingId").asText(), "mmmm:block_patch");
            if (found != null || !ContractJson.digest(expected).equals(ContractJson.digest(actual))) throw new ContractException("DEPENDENCY_CHANGED", "Built-in direct codec registration changed");
            found = digest;
        }
        if (found == null) throw new ContractException("OWNED_BLOCK_SOURCE_UNAVAILABLE", "Built-in direct codec is not registered");
        return found;
    }

    private ObjectNode ownedBlockPreflight(HostSession paired, ObjectNode context, ObjectNode input,
                                          String implementationDigest, Runnable active, Invocation invocation) {
        requireServerThread();
        MinecraftServer currentServer = server; HostRuntime currentRuntime = runtime;
        long generation = registryGeneration; String currentEpoch = epoch; SessionRoute route = sessionRoute(paired);
        String contextId = HostDispatcher.string(context, "contextId");
        Set<String> permissions = Set.of(invocation == null ? "mmmm:world_read" : "mmmm:world_write");
        Runnable checkpoint = () -> {
            active.run(); requireServerThread(); paired.checkOpen();
            if (server != currentServer || runtime != currentRuntime || registryGeneration != generation
                    || !java.util.Objects.equals(epoch, currentEpoch) || sessionRoute(paired) != route) {
                throw new ContractException("SESSION_EPOCH_MISMATCH", "Owned block observation route or generation changed");
            }
            if (!paired.context(contextId).equals(context)) throw new ContractException("STALE_CONTEXT", "Owned block context differs from its current owner");
            // Cheap current permission/player checks bracket each getter. The retained write plan,
            // full source profile and invocation are checked at the outer pre/post boundaries.
            new PlatformAuthority(null).check(paired, context, permissions, false); active.run();
        };
        Runnable admission = () -> {
            checkpoint.run();
            if (invocation != null) {
                PlatformAuthority authority = new PlatformAuthority(null);
                authority.check(paired, context, permissions, true); authority.checkInvocation(paired, invocation, true);
            }
            checkpoint.run();
        };
        ObjectNode before = null; ObjectNode receipt = null; RuntimeException failure = null;
        try {
            checkpoint.run(); OwnedBlockPatchPreflight.validateInput(context, input, Long.toString(generation));
            admission.run();
            if (!implementationDigest.equals(nativeBlockImplementation())) throw new ContractException("DEPENDENCY_CHANGED", "Direct codec implementation differs from its registration");
            checkpoint.run();
            before = NativeSourceFacts.observe(currentServer, Long.toString(generation), environment(), checkpoint::run);
            String hostDigest = ownedBlockHostDigest(before, implementationDigest);
            receipt = OwnedBlockPatchPreflight.inspect(loaded, level(context.path("dimension").asText()), context, input,
                    before, hostDigest, implementationDigest, Long.toString(generation), checkpoint);
        } catch (RuntimeException original) { failure = original; }
        try {
            checkpoint.run();
            if (before != null) {
                ObjectNode after = NativeSourceFacts.observe(currentServer, Long.toString(generation), environment(), checkpoint::run);
                ownedBlockHostDigest(after, implementationDigest);
                if (!NativeProfileAdmission.sourceDigest(before).equals(NativeProfileAdmission.sourceDigest(after))) {
                    throw new ContractException("TARGET_DRIFT", "Current direct block source facts changed during observation");
                }
            }
            admission.run(); checkpoint.run();
            if (receipt != null && "known".equals(receipt.path("status").asText())) {
                OwnedBlockPatchPreflight.requireCurrentCells(loaded, level(context.path("dimension").asText()), context, input,
                        Long.toString(generation), checkpoint);
            }
            checkpoint.run();
        } catch (RuntimeException current) {
            if (failure == null) failure = current; else if (current != failure) failure.addSuppressed(current);
        }
        if (failure != null) throw failure;
        return receipt;
    }

    private static String ownedBlockHostDigest(ObjectNode facts, String implementationDigest) {
        for (JsonNode mod : facts.path("mods")) {
            if (!"mmmm_host".equals(mod.path("modId").asText())) continue;
            JsonNode archives = mod.path("installation").path("archives");
            JsonNode roots = mod.path("runtimeRoots");
            if ("observed_origin_list".equals(mod.path("installation").path("status").asText())
                    && archives.isArray() && archives.size() == 1 && roots.isArray() && roots.size() == 1
                    && sameOwnedHostArchive(archives.get(0), roots.get(0), implementationDigest)) {
                int matches = 0;
                for (JsonNode archive : facts.path("archives")) if (sameOwnedHostArchive(archives.get(0), archive, implementationDigest)) matches++;
                if (matches == 1) return implementationDigest;
            }
            break;
        }
        throw new ContractException("OWNED_BLOCK_SOURCE_UNAVAILABLE", "Current ordinary host artifact does not match the registered direct codec");
    }

    private static boolean sameOwnedHostArchive(JsonNode left, JsonNode right, String digest) {
        for (JsonNode receipt : List.of(left, right)) {
            if (!"observed".equals(receipt.path("status").asText()) || !"container_input_bytes".equals(receipt.path("scope").asText())
                    || !digest.equals(receipt.path("sha256").asText())
                    || !("archive-sha256-" + digest).equals(receipt.path("sourceId").asText())
                    || !receipt.path("sizeBytes").isIntegralNumber() || !receipt.path("sizeBytes").canConvertToLong()
                    || receipt.path("sizeBytes").longValue() <= 0 || receipt.path("sizeBytes").longValue() > 64L * 1024 * 1024) return false;
        }
        return left.path("sizeBytes").longValue() == right.path("sizeBytes").longValue();
    }

    private ObjectNode collectSourceFacts(HostSession paired, ObjectNode context,
                                         HostDispatcher.InspectionControl control, CompletableFuture<ObjectNode> response,
                                         Set<String> required) {
        final MinecraftServer currentServer; final long generation; final String currentEpoch;
        synchronized (definitionCollection) { currentServer = server; generation = registryGeneration; currentEpoch = epoch; }
        String contextId = HostDispatcher.string(context, "contextId");
        NativeSourceFacts.Checkpoint checkpoint = () -> {
            control.checkpoint(); paired.checkOpen();
            if (response.isDone()) throw new ContractException("CANCELLATION_REQUESTED", "Source inspection response ended");
            if (server != currentServer || registryGeneration != generation || !java.util.Objects.equals(epoch, currentEpoch)) {
                throw new ContractException("SESSION_EPOCH_MISMATCH", "Source observation generation ended");
            }
        };
        checkpoint.check();
        requireServerThread();
        if (!paired.context(contextId).equals(context)) throw new ContractException("STALE_CONTEXT", "Source observation context differs from its installed owner");
        try {
            ObjectNode observation = NativeSourceFacts.observe(currentServer, Long.toString(generation), environment(), checkpoint);
            // 같은 inspect 분기의 원 permission을 사용하며 entry별 platform I/O를 추가하지 않는다.
            checkpoint.check();
            new PlatformAuthority(null).check(paired, context, required, false);
            if (!paired.context(contextId).equals(context)) throw new ContractException("STALE_CONTEXT", "Source observation owner changed");
            checkpoint.check();
            return observation;
        } catch (RuntimeException failure) {
            try { checkpoint.check(); }
            catch (RuntimeException current) { if (current != failure) failure.addSuppressed(current); }
            throw failure;
        }
    }

    private ObjectNode collectRegistryDefinitions(HostSession paired, ObjectNode context,
                                                 HostDispatcher.InspectionControl control, CompletableFuture<ObjectNode> response) {
        final MinecraftServer currentServer; final long generation; final String currentEpoch;
        synchronized (definitionCollection) { currentServer = server; generation = registryGeneration; currentEpoch = epoch; }
        String contextId = HostDispatcher.string(context, "contextId"); String contextDigest = HostDispatcher.string(context, "contextDigest");
        NativeDefinitionCollector.Checkpoint checkpoint = () -> {
            control.checkpoint(); paired.checkOpen();
            if (response.isDone()) throw new ContractException("CANCELLATION_REQUESTED", "Registry inspection response ended");
            if (server != currentServer || registryGeneration != generation || !java.util.Objects.equals(epoch, currentEpoch)) {
                throw new ContractException("SESSION_EPOCH_MISMATCH", "Registry observation generation ended");
            }
        };
        checkpoint.check();
        if (!paired.context(contextId).equals(context)) throw new ContractException("STALE_CONTEXT", "Registry observation context differs from its installed owner");
        final NativeDefinitionSlot.Ticket ticket;
        synchronized (definitionCollection) {
            if (server != currentServer || registryGeneration != generation || !java.util.Objects.equals(epoch, currentEpoch)) {
                throw new ContractException("SESSION_EPOCH_MISMATCH", "Registry observation generation ended before collection");
            }
            ticket = definitionCollection.begin(paired, currentServer, contextId, contextDigest, currentEpoch, generation);
        }
        NativeDefinitionCollector collector = NativeDefinitionCollector.production(checkpoint);
        try {
            ObjectNode observation = NativeRegistry.observe(collector);
            collector.finish();
            new PlatformAuthority(null).check(paired, context, Set.of("mmmm:world_read"), false);
            if (!paired.context(contextId).equals(context)) throw new ContractException("STALE_CONTEXT", "Registry observation owner changed");
            checkpoint.check();
            return observation;
        } catch (RuntimeException failure) {
            collector.stopped(failure); throw failure;
        } finally {
            NativeDefinitionCollector.Snapshot observed = collector.snapshot();
            synchronized (definitionCollection) {
                if (server == currentServer && registryGeneration == generation && java.util.Objects.equals(epoch, currentEpoch)) {
                    definitionCollection.publish(ticket, observed);
                } else definitionCollection.retire(ticket);
            }
        }
    }

    private String definitionAdmissionReason(HostSession paired, ObjectNode context) {
        // 실제 원자료 수집 여부만 진단한다. 최종 변환/실행 경로 승인으로 승격하지 않는다.
        synchronized (definitionCollection) {
            if (definitionCollection.hasRawObservation(paired, server, context.path("contextId").asText(),
                    context.path("contextDigest").asText(), epoch, registryGeneration)) {
                return "LOADED_DEFINITION_FINALITY_UNVERIFIED";
            }
        }
        return "LOADED_DEFINITION_UNAVAILABLE";
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
        @Override public boolean ready() { return server != null && epoch != null && !reloading && !stopping; }
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
        synchronized (routes) {
            HostSession current = session;
            if (current == null) throw new ContractException("SESSION_EXPIRED", "No paired session is installed");
            current.checkOpen(); return current;
        }
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
        patch.withObject("properties").putObject("expectedRegistryGeneration").put("type", "string").put("pattern", "^(0|[1-9][0-9]{0,18})$");
        patch.withArray("required").add("expectedState").add("desiredState").add("expectedRegistryGeneration");
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
        patchProperties.putObject("knownProducerId").put("const", OwnedBlockPatchPreflight.PRODUCER);
        patchProperties.putObject("preflightPin").put("type", "string").put("pattern", "^[0-9a-f]{64}$");
        patchProperties.putObject("directCoverage").put("const", "block_state_cells");
        patchProperties.putObject("exactUndoSupported").put("const", false);
        patchProperties.putObject("lossCode").put("const", OwnedBlockPatchPreflight.LOSS);
        var exactLimitations = patchProperties.putObject("limitations").putArray("const");
        OwnedBlockPatchPreflight.LIMITATIONS.forEach(exactLimitations::add);
        patchProperties.set("before", observed.deepCopy()); patchProperties.set("after", observed.deepCopy());
        patchOutput.putArray("required").add("kind").add("setBlockReportedSuccess").add("before").add("after").add("indirectEffects");
        patchOutput.withArray("required").add("knownProducerId").add("preflightPin").add("directCoverage")
                .add("exactUndoSupported").add("lossCode").add("limitations");
        ObjectNode commandOutput = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        commandOutput.putObject("properties").putObject("commandReturnInt32").put("type", "integer")
                .put("minimum", Integer.MIN_VALUE).put("maximum", Integer.MAX_VALUE);
        commandOutput.withObject("properties").putObject("completionClaim").put("const", "native_command_return_only");
        commandOutput.putArray("required").add("commandReturnInt32").add("completionClaim");
        ObjectNode calibrationOutput = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        calibrationOutput.putArray("required").add("completionClaim").add("nativeCallbackCount").add("nativeCallbackReturn");
        calibrationOutput.putObject("properties").putObject("completionClaim").put("const", "native_function_queue_observed");
        calibrationOutput.withObject("properties").putObject("nativeCallbackCount").put("type", "integer").put("minimum", 0).put("maximum", 256);
        var optionalReturn = calibrationOutput.withObject("properties").putObject("nativeCallbackReturn").putArray("oneOf");
        optionalReturn.addObject().put("type", "integer").put("minimum", Integer.MIN_VALUE).put("maximum", Integer.MAX_VALUE);
        optionalReturn.addObject().put("type", "null");
        ObjectNode callbackShape = calibrationOutput.putArray("allOf").addObject();
        callbackShape.putObject("if").putObject("properties").putObject("nativeCallbackCount").put("const", 1);
        callbackShape.putObject("then").putObject("properties").putObject("nativeCallbackReturn").put("type", "integer");
        callbackShape.putObject("else").putObject("properties").putObject("nativeCallbackReturn").put("type", "null");
        List<ObjectNode> result = new ArrayList<>();
        result.add(descriptor("mmmm:block_read", "mmmm:block_state_read", "read", point, observed, digest, "mmmm:world_read", "provider_completion"));
        ObjectNode directPatch = descriptor("mmmm:block_patch", "mmmm:block_state_patch", "write", patch, patchOutput, digest, "mmmm:world_write", "independent_readback");
        OwnedBlockPatchPreflight.LIMITATIONS.forEach(directPatch.withArray("limitations")::add);
        directPatch.withArray("limitations").add(OwnedBlockPatchPreflight.LOSS);
        contracts.validate("ActionDescriptor", directPatch); result.add(directPatch);
        result.add(descriptor("mmmm:command_execute", "mmmm:raw_command", "unknown", command, commandOutput, digest, "mmmm:command_execute", "independent_readback"));
        ObjectNode calibrationAction = descriptor("mmmm:calibration_command_execute", "mmmm:raw_command", "unknown", command,
                calibrationOutput, digest, "mmmm:command_execute", "independent_readback");
        calibrationAction.withArray("limitations").add("Only the exact immutable private normative47 calibration purpose route executes this action")
                .add("Native queue completion and optional callbacks are factual; independent readback and explicit source checks remain required");
        contracts.validate("ActionDescriptor", calibrationAction); result.add(calibrationAction);
        ObjectNode bootstrapAction = descriptor(NativeCalibrationBootstrap.ACTION_ID, "mmmm:calibration_bootstrap", "write",
                NativeCalibrationBootstrap.inputSchema(), NativeCalibrationBootstrap.outputSchema(), digest,
                "mmmm:command_execute", "independent_readback");
        bootstrapAction.withArray("limitations").add("Only the exact immutable private numeric calibration bootstrap purpose route executes this action")
                .add("Bootstrap approval grants no ordinary verified-profile writes; reload invalidates this route");
        contracts.validate("ActionDescriptor", bootstrapAction); result.add(bootstrapAction);
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
        if (server == null || reloading || stopping || !server.isSameThread()) throw new ContractException("HOST_NOT_READY", "This operation requires the active ready server thread");
    }
    private void disconnect() {
        definitionCollection.retireAll();
        final List<HostSession> owners; final List<SessionRoute> retired;
        final PairedLoopbackServer oldEndpoint; final HostRuntime oldRuntime; final HostSession oldSession;
        final NativeCompatibilityApprovals oldCompatibility;
        final NativeCompatibilityMetadataResolver oldMetadata;
        synchronized (routes) {
            owners = List.copyOf(routes.keySet()); retired = List.copyOf(routes.values());
            oldEndpoint = endpoint; oldRuntime = runtime; oldSession = session;
            oldCompatibility = compatibilityApprovals; compatibilityApprovals = null;
            oldMetadata = compatibilityMetadataResolver; compatibilityMetadataResolver = null;
            owners.forEach(HostSession::close); if (oldSession != null) oldSession.close();
            routes.clear(); routeOrder.clear(); calibrationOffers.clear(); bootstrapOffers.clear(); nativeHistory.clear(); nativeHistoryCount = 0; nativeHistoryBytes = 0;
            completedReadonlyPairings.clear();
            invocationRoutes.clear(); installedSources = Map.of(); installedActions = Set.of(); installedContexts = List.of();
            endpoint = null; runtime = null; session = null;
        }
        if (oldMetadata != null) oldMetadata.close();
        if (oldCompatibility != null) oldCompatibility.close();
        retired.forEach(route -> route.endpoint().close());
        if (oldEndpoint != null) oldEndpoint.close();
        if (oldRuntime != null) oldRuntime.close();
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
