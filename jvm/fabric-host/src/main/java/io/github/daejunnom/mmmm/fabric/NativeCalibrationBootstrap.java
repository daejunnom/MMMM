package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.fabric.mixin.FixedPathPackReadAccess;
import io.github.daejunnom.mmmm.host.AnonymousBridge;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.host.NativeInvocationReservations;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.core.registries.Registries;
import net.minecraft.resources.FileToIdConverter;
import net.minecraft.resources.Identifier;
import net.minecraft.server.ServerFunctionLibrary;
import net.minecraft.server.packs.FixedPathPackResources;
import net.minecraft.server.packs.repository.Pack;

/** A separately approved, fresh-only installation. Numeric run approval is not installation authority. */
final class NativeCalibrationBootstrap implements HostDispatcher.PurposeRoute, AutoCloseable {
    static final String PURPOSE = "numeric_calibration_bootstrap/1";
    static final String ACTION_ID = "mmmm:calibration_bootstrap_execute";
    static final String PACK_TARGET = "calibration-bootstrap-pack";
    private static final Set<String> MANIFEST_FIELDS = Set.of("kind", "purpose", "selectionDigest", "hostEpoch",
            "registryGeneration", "runtimeSourceFactsDigest", "suiteDigest", "recipeSha256", "plan", "sourceBundle", "programs");
    private static final Set<String> PROGRAM_FIELDS = Set.of("caseId", "functionId", "objective", "storage", "initializationCommands");
    private static final int MAX_TARGETS = 95, MAX_PACKS = 256;

    /** Only the closed, protected bootstrap manifest constructs a program. */
    static final class Program {
        private final String caseId, functionId, objective, storage;
        private final List<String> initializationCommands;
        private Program(ObjectNode value) {
            HostDispatcher.exactFields(value, PROGRAM_FIELDS);
            caseId = text(value, "caseId"); functionId = text(value, "functionId");
            objective = text(value, "objective"); storage = text(value, "storage");
            String expectedObjective = "mcal" + ContractJson.sha256(caseId.getBytes(StandardCharsets.UTF_8)).substring(0, 11);
            if (!caseId.matches("[a-z][a-z0-9_]{0,127}") || !functionId.matches("mmmm_calibration:" + caseId + "/[a-f0-9]{24}")
                    || !objective.equals(expectedObjective) || !storage.equals("mmmm:calibration/" + caseId)
                    || !value.path("initializationCommands").isArray() || value.path("initializationCommands").size() != 1
                    || !value.path("initializationCommands").get(0).isTextual()
                    || !value.path("initializationCommands").get(0).textValue().equals("scoreboard objectives add " + objective + " dummy")) throw invalid();
            initializationCommands = List.of(value.path("initializationCommands").get(0).textValue());
        }
        String caseId() { return caseId; }
        String functionId() { return functionId; }
        String objective() { return objective; }
        String storage() { return storage; }
        List<String> initializationCommands() { return initializationCommands; }
    }

    private static final class Prepared {
        private final NativeCalibrationPackFiles.PreparedFiles files;
        private final NativeCalibrationStorageAcquisition.Prepared storage;
        private final ObjectNode images;
        private Prepared(NativeCalibrationPackFiles.PreparedFiles files, NativeCalibrationStorageAcquisition.Prepared storage, ObjectNode images) {
            this.files = files; this.storage = storage; this.images = images.deepCopy();
        }
        private void recheck(Runnable current) { checked(() -> { files.checkCurrent(current); storage.recheck(current); return null; }, current); }
    }

    /** Only an actual attempted effect can produce this in-process diagnostic. It is never a ready or replay grant. */
    static final class InterruptedBootstrap extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient Object fileFacts;
        private final transient List<Integer> initializationReturns;
        private final transient CompletionStage<Void> actualReload;
        private final boolean reloadRequested, reloadCompleted;
        private InterruptedBootstrap(Object files, List<Integer> returns, boolean requested, boolean completed, CompletionStage<Void> actualReload) {
            super("The original bootstrap stopped after a possibly partial effect");
            fileFacts = files; initializationReturns = List.copyOf(returns); reloadRequested = requested; reloadCompleted = completed;
            this.actualReload = actualReload;
        }
        Object fileFacts() { return fileFacts; }
        List<Integer> initializationReturns() { return initializationReturns; }
        boolean reloadRequested() { return reloadRequested; }
        boolean reloadSuccessObserved() { return reloadCompleted; }
        CompletionStage<Void> actualReload() { return actualReload; }
    }

    private static final class Accepted {
        private final Invocation original;
        private final String digest;
        private final CompletableFuture<ProviderResult> result = new CompletableFuture<>();
        private volatile CompletionStage<Void> actualReload;
        private final Attempt attempt;
        private Accepted(NativeCalibrationBootstrap owner, Invocation invocation) {
            original = invocation; digest = ContractJson.digest(invocation.wire());
            attempt = new Attempt(owner, invocation, result);
        }
    }

    /** Historical facts from an actual admission. It contains no session, approval, request control or replay entry. */
    static final class Attempt {
        private record ResultState(ObjectNode result, Throwable failure) { }
        private record ReloadState(String outcome, Throwable failure) { }
        private final MinecraftServer owner;
        private final Invocation original;
        private final String invocationDigest, bundleDigest, manifestDigest, gameInstanceId, worldId;
        private final List<Program> programs;
        private final Set<String> targetIds;
        private final List<NativeLoadedCalibrationSources.ExpectedSource<Identifier>> expectedSources;
        private volatile ResultState result;
        private volatile ReloadState reload = new ReloadState("not_attempted", null);
        private volatile String effectPhase = "accepted";
        private volatile ObjectNode fileFacts;
        private volatile int initializationAttemptedCount;
        private volatile List<Integer> initializationReturns = List.of();

        private Attempt(NativeCalibrationBootstrap bootstrap, Invocation invocation, CompletionStage<ProviderResult> actualResult) {
            owner = bootstrap.server; original = invocation; invocationDigest = ContractJson.digest(invocation.wire());
            bundleDigest = bootstrap.bundleDigest; manifestDigest = bootstrap.manifestDigest;
            gameInstanceId = invocation.context().path("environment").path("gameInstanceId").asText();
            worldId = invocation.context().path("environment").path("worldId").asText();
            programs = bootstrap.programs;
            Set<String> ids = new HashSet<>(); ids.add(PACK_TARGET);
            for (Program program : programs) {
                ids.add("calibration-objective-" + program.objective());
                ids.add("calibration-storage-" + ContractJson.sha256(program.storage().getBytes(StandardCharsets.UTF_8)));
            }
            targetIds = Set.copyOf(ids);
            var converter = new FileToIdConverter(Registries.elementsDirPath(ServerFunctionLibrary.TYPE_KEY), ".mcfunction");
            var expected = new ArrayList<NativeLoadedCalibrationSources.ExpectedSource<Identifier>>(47);
            for (Program program : programs) {
                Identifier id = Identifier.parse(program.functionId());
                String path = "data/mmmm_calibration/function/" + program.functionId().substring("mmmm_calibration:".length()) + ".mcfunction";
                JsonNode matched = null;
                for (JsonNode entry : bootstrap.manifest.path("sourceBundle").path("entries")) {
                    if (path.equals(entry.path("path").asText())) matched = entry;
                }
                if (matched == null) throw invalid();
                expected.add(new NativeLoadedCalibrationSources.ExpectedSource<>(id, converter.idToFile(id),
                        java.util.HexFormat.of().parseHex(matched.path("rawBytesHex").asText())));
            }
            expectedSources = List.copyOf(expected);
            actualResult.whenComplete((value, failure) -> result = new ResultState(value == null ? null : value.wire().deepCopy(), failure));
        }

        Invocation original() { return original; }
        String invocationDigest() { return invocationDigest; }
        String sourceBundleDigest() { return bundleDigest; }
        String frozenManifestDigest() { return manifestDigest; }
        void requireScope(ObjectNode context) {
            if (!stringSet(context.path("scope").path("externalTargetIds")).containsAll(targetIds)) throw invalid();
        }
        void requireActualOwner(MinecraftServer actual, String actualGame, String actualWorld) {
            if (actual != owner || !gameInstanceId.equals(actualGame) || !worldId.equals(actualWorld)) throw invalid();
        }
        private void startReload() { effectPhase = "reload_call_attempted"; reload = new ReloadState("call_attempted_without_future", null); }
        private void retainReload(CompletionStage<Void> actual) {
            Objects.requireNonNull(actual); effectPhase = "reload_future_returned";
            reload = new ReloadState("pending", null);
            actual.whenComplete((ignored, failure) -> reload = new ReloadState(failure == null ? "completed" : "failed", failure));
        }
        private ObjectNode history() {
            ResultState originalResult = result; ReloadState actual = reload;
            ObjectNode history = ContractJson.newObject().put("resultTerminal", originalResult != null).put("effectPhase", effectPhase)
                    .put("initializationAttemptedCount", initializationAttemptedCount).put("reloadOutcome", actual.outcome());
            if (originalResult == null || originalResult.result() == null) history.putNull("originalResult");
            else history.set("originalResult", originalResult.result().deepCopy());
            history.set("originalFailure", originalResult == null ? com.fasterxml.jackson.databind.node.NullNode.instance : throwable(originalResult.failure()));
            history.set("reloadFailure", throwable(actual.failure()));
            ObjectNode installed = fileFacts;
            if (installed == null) history.putNull("fileFacts"); else history.set("fileFacts", installed.deepCopy());
            ArrayNode returns = history.putArray("initializationReturns"); initializationReturns.forEach(returns::add);
            return history;
        }

        ObjectNode observeSuccessor(MinecraftServer actual, ServerLevel level, HostSession currentOwner,
                                    ObjectNode context, Runnable current) {
            return checked(() -> {
                current.run(); long from = Integer.toUnsignedLong(actual.getTickCount());
                ObjectNode response = ContractJson.newObject().put("format", "mmmm.native.calibration-bootstrap-successor/1")
                        .put("frozenManifestDigest", manifestDigest).put("sourceBundleDigest", bundleDigest);
                response.set("originalInvocation", original.wire().deepCopy()); response.set("currentContext", context.deepCopy());
                response.set("history", history());
                ObjectNode observation = response.putObject("observation").put("format", "mmmm.native.calibration-bootstrap-observation/1")
                        .put("observedFromTick", Long.toString(from)).put("observedToTick", Long.toString(from));
                observation.putObject("pack").put("status", "unknown").put("reason", "readonly_pack_observer_unavailable")
                        .put("identityContinuity", "unproven");
                ObjectNode loaded = observation.putObject("loadedSources").put("status", "unknown").put("causalLink", "unproven");
                ArrayNode functions = loaded.putArray("functions"); loaded.putNull("failure");
                try {
                    var sources = NativeLoadedCalibrationSources.observe(actual, expectedSources, current::run);
                    for (var function : sources.functions()) {
                        current.run(); functions.addObject().put("functionId", function.functionId().toString())
                                .put("resourceId", function.resourceId().toString()).put("sourcePackId", function.sourcePackId())
                                .put("rawSha256", function.sha256()).put("byteLength", function.bytes().length);
                    }
                    sources.checkCurrent(current::run); current.run(); loaded.put("status", "known");
                } catch (RuntimeException failure) {
                    loaded.set("failure", observedFailure(failure, current));
                }
                ObjectNode images = observation.putObject("targetImages").put("status", "unknown");
                images.putArray("targets"); images.putNull("failure");
                try {
                    boolean known = true; int bytes = 0;
                    for (Program program : programs) {
                        current.run();
                        String objectiveId = "calibration-objective-" + program.objective();
                        String storageId = "calibration-storage-" + ContractJson.sha256(program.storage().getBytes(StandardCharsets.UTF_8));
                        ArrayNode bindings = ContractJson.newObject().putArray("bindings");
                        bindings.addObject().put("targetId", objectiveId).put("kind", "objective").put("objective", program.objective());
                        bindings.addObject().put("targetId", storageId).put("kind", "owned_storage").put("storage", program.storage())
                                .putArray("ownedSubtrees").add("inputs").add("invocation");
                        var selected = NativeCalibrationTargetImages.select(program.caseId(), program.functionId(), bindings);
                        var pair = NativeCalibrationTargetImages.observeSelected(actual, level, currentOwner, context, selected, current::run);
                        byte[] objective = pair.objectiveBytes(), storage = pair.storageBytes();
                        // Preserve a bounded completed prefix. No omitted target is represented as absent or known.
                        if ((long) bytes + objective.length + storage.length > 192L * 1024) throw limit();
                        if (!appendSuccessorPair(response, objectiveId, objective, pair.objectiveSha256(),
                                storageId, storage, pair.storageSha256())) throw limit();
                        bytes += objective.length + storage.length;
                        known &= pair.objectiveFullTargetKnown() && pair.storageFullTargetKnown(); current.run();
                    }
                    images.put("status", known ? "known" : "unknown");
                } catch (RuntimeException failure) {
                    images.set("failure", observedFailure(failure, current));
                }
                observation.put("observedToTick", Long.toString(Integer.toUnsignedLong(actual.getTickCount())));
                current.run(); bounded(response); return response;
            }, current);
        }
        private static void addTarget(ArrayNode rows, String id, byte[] raw, String sha) {
            rows.addObject().put("targetId", id).put("rawBytesHex", java.util.HexFormat.of().formatHex(raw)).put("rawSha256", sha);
        }
    }

    /** Wire capacity only. This formatter creates no native observation or permission. */
    static boolean appendSuccessorPair(ObjectNode response, String objectiveId, byte[] objective, String objectiveSha,
                                       String storageId, byte[] storage, String storageSha) {
        ObjectNode observation = ContractJson.object(response.path("observation"));
        ObjectNode images = ContractJson.object(observation.path("targetImages"));
        if (!(images.path("targets") instanceof ArrayNode targets)) throw limit();
        String actualTick = text(observation, "observedToTick");
        if (!actualTick.matches("[0-9]{1,10}") || Long.parseLong(actualTick) > 0xffff_ffffL) throw limit();
        int originalSize = targets.size(); boolean retained = false; Throwable primary = null;
        try {
            Attempt.addTarget(targets, objectiveId, objective, objectiveSha);
            Attempt.addTarget(targets, storageId, storage, storageSha);
            // The actual original/history/loaded/current fields are already in
            // this response. Reserve the bounded failure wire and the maximum
            // growth of the actual final unsigned tick before admitting a pair.
            retained = withinFrame(response, 16 * 1024 + 10 - actualTick.length(), 256);
            return retained;
        } catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            if (!retained) {
                try { while (targets.size() > originalSize) targets.remove(targets.size() - 1); }
                catch (RuntimeException | Error cleanup) { if (primary == null) throw cleanup; preserve(primary, cleanup); }
            }
        }
    }

    /** Bounded factual throwable graph. Messages and stacks can contain local paths and are deliberately excluded. */
    static JsonNode throwable(Throwable actual) {
        return throwable(actual, new IdentityHashMap<>(), new int[] { 0 }, 0);
    }
    private static JsonNode observedFailure(RuntimeException actual, Runnable post) {
        try { post.run(); }
        catch (RuntimeException | Error after) { preserve(actual, after); throw actual; }
        return throwable(actual);
    }
    private static JsonNode throwable(Throwable actual, IdentityHashMap<Throwable, Boolean> seen, int[] count, int depth) {
        if (actual == null) return com.fasterxml.jackson.databind.node.NullNode.instance;
        // Every emitted diagnostic object consumes the budget, including a
        // depth/cycle boundary. Callers stop expansion before no slot remains.
        if (count[0] >= 32) throw limit();
        count[0]++;
        ObjectNode node = ContractJson.newObject().put("type", actual.getClass().getName());
        if (actual instanceof ContractException contract && contract.code().matches("[A-Z][A-Z0-9_]{0,127}")) node.put("code", contract.code());
        else node.putNull("code");
        node.putNull("cause"); ArrayNode suppressed = node.putArray("suppressed");
        if (depth >= 8 || seen.put(actual, Boolean.TRUE) != null) return node.put("truncated", true);
        boolean truncated = false;
        if (actual.getCause() != null) {
            if (count[0] >= 32) truncated = true;
            else node.set("cause", throwable(actual.getCause(), seen, count, depth + 1));
        }
        Throwable[] children = actual.getSuppressed();
        for (int i = 0; i < children.length && i < 8; i++) {
            if (count[0] >= 32) { truncated = true; break; }
            suppressed.add(throwable(children[i], seen, count, depth + 1));
        }
        return node.put("truncated", truncated || children.length > 8);
    }

    private final ContractJson contracts;
    private final HostSession session;
    private final Clock clock;
    private final NativeCalibrationApproval.Tasks tasks;
    private final NativeCalibrationApproval.Current current;
    private final Consumer<Attempt> retainAccepted;
    private final MinecraftServer server;
    private final Supplier<ServerPlayer> player;
    private final Function<String, ServerLevel> levels;
    private final ObjectNode manifest, step;
    private final NativePlanApproval plan;
    private final NativeInvocationReservations reservations;
    private final NativeCalibrationPackFiles.SealedFiles source;
    private final List<Program> programs;
    private final String bundleDigest, manifestDigest, contextId;
    private final AtomicBoolean closed = new AtomicBoolean(), activated = new AtomicBoolean();
    private volatile Accepted accepted;

    NativeCalibrationBootstrap(ContractJson contracts, ObjectNode input, HostSession session, Clock clock,
                               NativeCalibrationApproval.Tasks tasks, NativeCalibrationApproval.Current current,
                               Consumer<Attempt> retainAccepted, MinecraftServer server, Supplier<ServerPlayer> player,
                               Function<String, ServerLevel> levels) {
        this.contracts = Objects.requireNonNull(contracts); this.session = Objects.requireNonNull(session);
        this.clock = Objects.requireNonNull(clock); this.tasks = Objects.requireNonNull(tasks); this.current = Objects.requireNonNull(current);
        this.retainAccepted = Objects.requireNonNull(retainAccepted); this.server = Objects.requireNonNull(server);
        this.player = Objects.requireNonNull(player); this.levels = Objects.requireNonNull(levels);
        bounded(input); manifest = input.deepCopy(); HostDispatcher.exactFields(manifest, MANIFEST_FIELDS);
        if (!"native_calibration_bootstrap_approval/1".equals(text(manifest, "kind")) || !PURPOSE.equals(text(manifest, "purpose"))
                || !session.epoch().equals(text(manifest, "hostEpoch")) || session.verifiedWriteProfile()) throw invalid();
        for (String field : Set.of("selectionDigest", "runtimeSourceFactsDigest", "suiteDigest", "recipeSha256")) sha(manifest, field);
        if (!text(manifest, "suiteDigest").equals(text(manifest, "recipeSha256"))
                || !text(manifest, "registryGeneration").matches("[1-9][0-9]{0,18}")) throw invalid();
        ObjectNode inner = ContractJson.object(manifest.path("plan"));
        if (!inner.path("steps").isArray() || inner.path("steps").size() != 1
                || !inner.path("nativeExecutions").isArray() || !inner.path("nativeExecutions").isEmpty()
                || !inner.path("contextPins").isArray() || inner.path("contextPins").size() != 1) throw invalid();
        plan = new NativePlanApproval(contracts, inner, clock); step = ContractJson.object(inner.path("steps").get(0)).deepCopy();
        if (!ACTION_ID.equals(text(step, "actionId"))) throw invalid();
        contextId = text(step, "contextId");
        source = NativeCalibrationPackFiles.SealedFiles.fromPrivateRustBundle(ContractJson.object(manifest.path("sourceBundle")));
        bundleDigest = sha(ContractJson.object(manifest.path("sourceBundle")), "bundleDigest");
        ObjectNode arguments = ContractJson.newObject().put("sourceBundleDigest", bundleDigest);
        if (!ContractJson.digest(arguments).equals(text(step, "argumentsDigest"))) throw invalid();
        if (!manifest.path("programs").isArray() || manifest.path("programs").size() != 47) throw invalid();
        List<Program> parsed = new ArrayList<>(); Set<String> cases = new HashSet<>(), functions = new HashSet<>(), targets = new HashSet<>();
        targets.add(PACK_TARGET);
        for (JsonNode value : manifest.path("programs")) {
            Program program = new Program(ContractJson.object(value));
            if (!cases.add(program.caseId()) || !functions.add(program.functionId())) throw invalid();
            String path = "data/mmmm_calibration/function/" + program.functionId().substring("mmmm_calibration:".length()) + ".mcfunction";
            JsonNode matched = null;
            for (JsonNode entry : manifest.path("sourceBundle").path("entries")) if (path.equals(entry.path("path").asText())) {
                if (matched != null) throw invalid(); matched = entry;
            }
            if (matched == null || !matched.path("rawSha256").asText().matches("[a-f0-9]{64}")
                    || !program.functionId().endsWith("/" + matched.path("rawSha256").asText().substring(0, 24))) throw invalid();
            targets.add("calibration-objective-" + program.objective());
            targets.add("calibration-storage-" + ContractJson.sha256(program.storage().getBytes(StandardCharsets.UTF_8)));
            parsed.add(program);
        }
        if (targets.size() != MAX_TARGETS || !stringSet(step.path("resourcesRead")).equals(targets)
                || !stringSet(step.path("resourcesWritten")).equals(targets)) throw invalid();
        Set<String> conditions = new HashSet<>();
        if (!step.path("preconditions").isArray() || step.path("preconditions").size() != MAX_TARGETS) throw invalid();
        for (JsonNode value : step.path("preconditions")) {
            HostDispatcher.exactFields(ContractJson.object(value), Set.of("kind", "subject", "expected", "coverage"));
            if (!"resource_hash".equals(value.path("kind").asText()) || !"full_target".equals(value.path("coverage").asText())
                    || !conditions.add(value.path("subject").asText()) || !value.path("expected").asText().matches("[a-f0-9]{64}")) throw invalid();
        }
        if (!conditions.equals(targets)) throw invalid();
        programs = List.copyOf(parsed); reservations = new NativeInvocationReservations(plan.expiresAt(), clock);
        checkContext(session.context(contextId)); manifestDigest = ContractJson.digest(manifest);
    }

    String selectionDigest() { return text(manifest, "selectionDigest"); }
    String manifestDigest() { return manifestDigest; }
    String registryGeneration() { return text(manifest, "registryGeneration"); }
    String runtimeSourceFactsDigest() { return text(manifest, "runtimeSourceFactsDigest"); }
    void activate() { if (closed.get() || !clock.instant().isBefore(plan.expiresAt())) throw invalid(); activated.set(true); }

    private void checkContext(ObjectNode context) {
        if (!plan.principalId().equals(session.principalRef()) || !plan.principalId().equals(context.path("principalRef").asText())
                || !plan.projectId().equals(context.path("projectId").asText()) || !plan.policyRevision().equals(context.path("policyRevision").asText())
                || !text(step, "contextDigest").equals(context.path("contextDigest").asText())) throw invalid();
        Set<String> actual = stringSet(context.path("scope").path("externalTargetIds"));
        if (!actual.containsAll(stringSet(step.path("resourcesWritten")))) throw invalid();
    }

    private Runnable control(HostSession owner, ObjectNode context, HostDispatcher.InspectionControl request) {
        return () -> {
            request.checkpoint();
            if (owner != session || closed.get() || !activated.get() || session.verifiedWriteProfile()) throw invalid();
            session.checkOpen();
            if (!server.isSameThread() || !context.equals(session.context(contextId))) throw invalid();
            checkContext(context); current.check(session, context, request::checkpoint, false); request.checkpoint();
        };
    }

    private void check(Invocation original, Runnable control, boolean sources) {
        control.run();
        if (!clock.instant().isBefore(original.deadlineAt()) || !clock.instant().isBefore(plan.expiresAt())) throw new ContractException("DEADLINE_EXCEEDED", "The original bootstrap deadline or plan expiry has elapsed");
        if (!contextId.equals(original.contextId()) || !original.context().equals(session.context(contextId))) throw invalid();
        for (String field : Set.of("stepId", "bindingId", "actionId", "actionDigest", "implementationDigest", "argumentsDigest", "contextDigest"))
            if (!step.path(field).equals(original.wire().path(field))) throw invalid();
        HostDispatcher.exactFields(original.arguments(), Set.of("sourceBundleDigest"));
        if (!bundleDigest.equals(original.arguments().path("sourceBundleDigest").asText())) throw invalid();
        current.check(session, original.context(), control, sources); control.run();
    }

    private Prepared observe(ObjectNode context, Runnable control) {
        control.run(); long fromTick = Integer.toUnsignedLong(server.getTickCount());
        ServerLevel level = levels.apply(context.path("dimension").asText());
        if (level == null || level.getServer() != server || server.getLevel(level.dimension()) != level) throw invalid();
        var files = NativeCalibrationPackFiles.prepare(server, level, session, context, source, control);
        var state = NativeCalibrationStorageAcquisition.prepare(server, level, session, context, programs, control);
        ObjectNode images = ContractJson.newObject().put("format", "mmmm.native.calibration-target-images/1")
                .put("protocolVersion", ContractJson.VERSION).put("contextId", contextId).put("contextDigest", context.path("contextDigest").asText())
                .put("runtimeSourceFactsDigest", runtimeSourceFactsDigest()).put("hostArtifactDigest", step.path("implementationDigest").asText())
                .put("registryGeneration", registryGeneration()).put("observedFromTick", Long.toString(fromTick))
                .put("observedToTick", Long.toString(Integer.toUnsignedLong(server.getTickCount()))).put("observedAt", Instant.now().toString());
        images.set("environment", context.path("environment").deepCopy()); ArrayNode targetRows = images.putArray("targets");
        targetRows.add(files.beforeTargets()); state.beforeTargets().forEach(targetRows::add);
        if (targetRows.size() != MAX_TARGETS) throw invalid();
        Set<String> ids = new HashSet<>();
        for (JsonNode row : targetRows) {
            if (!ids.add(row.path("targetId").asText())) throw invalid();
            JsonNode condition = null;
            for (JsonNode candidate : step.path("preconditions")) if (candidate.path("subject").asText().equals(row.path("targetId").asText())) { condition = candidate; break; }
            if (condition == null || !condition.path("expected").asText().equals(row.path("rawSha256").asText())) throw new ContractException("TARGET_DRIFT", "The actual bootstrap absence differs from the frozen requirement");
        }
        bounded(images); Prepared prepared = new Prepared(files, state, images); prepared.recheck(control); return prepared;
    }

    ObjectNode observeState(HostSession owner, ObjectNode context, String requestedBundle, HostDispatcher.InspectionControl request) {
        Runnable gate = control(owner, context, request);
        return checked(() -> {
            gate.run(); if (!bundleDigest.equals(requestedBundle) || !clock.instant().isBefore(plan.expiresAt())) throw invalid();
            current.check(session, context, gate, true); Prepared actual = observe(context, gate);
            current.check(session, context, gate, true); return actual.images.deepCopy();
        }, gate);
    }

    @Override public CompletionStage<ObjectNode> prepare(HostSession owner, Invocation original, HostDispatcher.InspectionControl request) {
        return tasks.submit(() -> {
            Runnable gate = control(owner, original.context(), request);
            return checked(() -> {
                check(original, gate, true); Prepared actual = observe(original.context(), gate); check(original, gate, true);
                ObjectNode ready = ContractJson.newObject().put("format", "mmmm.native.calibration-bootstrap-ready/1")
                        .put("invocationId", original.invocationId()).put("invocationDigest", ContractJson.digest(original.wire()))
                        .put("sourceBundleDigest", bundleDigest);
                ready.set("targetImages", actual.images.deepCopy()); bounded(ready); return ready;
            }, () -> check(original, gate, true));
        });
    }

    @Override public CompletionStage<ProviderResult> dispatch(HostSession owner, Invocation original, HostDispatcher.InspectionControl request) {
        var response = new CompletableFuture<ProviderResult>();
        tasks.submit(() -> {
            Runnable gate = control(owner, original.context(), request);
            try {
                check(original, gate, true); Accepted previous = accepted;
                if (previous != null) {
                    if (!previous.digest.equals(ContractJson.digest(original.wire())) || !reservations.containsExact(original)) throw invalid();
                    copy(previous.result, response); return null;
                }
                Prepared actual = observe(original.context(), gate); Accepted admitted;
                synchronized (this) {
                    if (accepted != null) throw invalid();
                    actual.recheck(gate); check(original, gate, true);
                    var candidate = reservations.inspect(original, true); reservations.admit(candidate);
                    admitted = new Accepted(this, original); accepted = admitted;
                }
                // A failed publication retains the exact admitted identity and may not execute or rebind it.
                try { retainAccepted.accept(admitted.attempt); } catch (RuntimeException | Error failure) { admitted.result.completeExceptionally(failure); throw failure; }
                copy(admitted.result, response); execute(admitted, actual, gate, request);
            } catch (RuntimeException | Error failure) {
                Throwable primary = finish(failure, () -> check(original, gate, true));
                Accepted retained = accepted;
                if (retained != null && retained.digest.equals(ContractJson.digest(original.wire()))) retained.result.completeExceptionally(primary);
                response.completeExceptionally(primary);
            }
            return null;
        }).whenComplete((ignored, failure) -> { if (failure != null) response.completeExceptionally(failure); });
        return response.minimalCompletionStage();
    }

    private void execute(Accepted admitted, Prepared prepared, Runnable gate, HostDispatcher.InspectionControl request) {
        Object files = null; List<Integer> returns = new ArrayList<>(); boolean requested = false;
        try {
            check(admitted.original, gate, true); prepared.recheck(gate);
            admitted.attempt.effectPhase = "pack_attempted";
            var installed = prepared.files.execute(admitted.original, gate); files = installed;
            admitted.attempt.fileFacts = installed.toWire(); admitted.attempt.effectPhase = "pack_created";
            check(admitted.original, gate, true); admitted.attempt.effectPhase = "storage_acquire_attempted";
            prepared.storage.acquire(gate); admitted.attempt.effectPhase = "storage_acquired";
            prepared.storage.recheck(gate); check(admitted.original, gate, true);
            ServerPlayer actualPlayer = player.get(); ServerLevel level = levels.apply(admitted.original.context().path("dimension").asText());
            if (actualPlayer == null || actualPlayer.level() != level) throw invalid();
            var commandSource = NativeCommands.source(actualPlayer, level, admitted.original.context());
            for (Program program : programs) for (String command : program.initializationCommands()) {
                check(admitted.original, gate, false); NativeCommandDispatch.requireIdle(server);
                var parsed = server.getCommands().getDispatcher().parse(new StringReader(command), commandSource);
                admitted.attempt.effectPhase = "objective_attempted"; admitted.attempt.initializationAttemptedCount++;
                int returned = NativeCommandDispatch.execute(server, parsed); returns.add(returned);
                admitted.attempt.initializationReturns = List.copyOf(returns);
                if (returned <= 0) throw new ContractException("CALIBRATION_BOOTSTRAP_INIT_FAILED", "The actual objective initialization did not report success");
                prepared.storage.recheck(gate); check(admitted.original, gate, false);
            }
            check(admitted.original, gate, true);
            var repository = server.getPackRepository(); admitted.attempt.effectPhase = "repository_reload_attempted";
            repository.reload(); check(admitted.original, gate, true);
            Pack chosen = null; int available = 0;
            for (Pack pack : repository.getAvailablePacks()) {
                gate.run(); if (++available > MAX_PACKS) throw limit();
                if (pack.getId().equals(installed.repositoryId())) { if (chosen != null) throw invalid(); chosen = pack; }
            }
            if (chosen == null) throw new ContractException("CALIBRATION_BOOTSTRAP_PACK_UNAVAILABLE", "The actual repository did not expose the installed pack");
            requireRoot(chosen, installed.createdPackRoot(), gate);
            List<String> selection = new ArrayList<>();
            for (String id : repository.getSelectedIds()) { gate.run(); if (selection.size() == MAX_PACKS || selection.contains(id)) throw limit(); selection.add(id); }
            if (!selection.contains(chosen.getId())) { if (selection.size() == MAX_PACKS) throw limit(); selection.add(chosen.getId()); }
            check(admitted.original, gate, true); requested = true; admitted.attempt.startReload();
            // Reload is the final effect. Its native START hook retires this route; no next write follows it.
            var reload = server.reloadResources(List.copyOf(selection));
            admitted.actualReload = reload.minimalCompletionStage();
            admitted.attempt.retainReload(admitted.actualReload);
            Object finalFiles = files; List<Integer> finalReturns = List.copyOf(returns);
            // Bound observation without cancelling/completing the engine's own future or claiming its effects stopped.
            var observed = new CompletableFuture<Void>();
            reload.whenComplete((value, failure) -> { if (failure == null) observed.complete(null); else observed.completeExceptionally(failure); });
            request.whenStopped(() -> observed.completeExceptionally(new ContractException("CANCELLATION_REQUESTED", "The original bootstrap reply has ended")));
            long remaining = Duration.between(clock.instant(), admitted.original.deadlineAt()).toNanos();
            observed.orTimeout(Math.max(1, Math.min(remaining, TimeUnit.SECONDS.toNanos(30))), TimeUnit.NANOSECONDS);
            observed.whenComplete((ignored, failure) -> completeReload(admitted, finalFiles, finalReturns, gate, request, failure));
        } catch (CommandSyntaxException | RuntimeException | Error primary) {
            preserve(primary, new InterruptedBootstrap(files, returns, requested, false, admitted.actualReload));
            admitted.result.completeExceptionally(finish(primary, () -> check(admitted.original, gate, false)));
        }
    }

    private void completeReload(Accepted admitted, Object files, List<Integer> returns, Runnable gate,
                                HostDispatcher.InspectionControl request, Throwable failure) {
        try {
            tasks.submit(() -> {
                Throwable terminal = failure;
                if (terminal == null) {
                    try {
                        check(admitted.original, gate, false);
                        ObjectNode output = ContractJson.newObject().put("completionClaim", "bootstrap_reload_observation_only")
                                .put("sourceBundleDigest", bundleDigest).put("installedFileCount", 48)
                                .put("initializedObjectiveCount", returns.size()).put("reloadOutcome", "completed");
                        admitted.result.complete(ProviderResult.complete(contracts, output, "unknown"));
                    } catch (RuntimeException | Error post) { terminal = post; }
                } else terminal = finish(terminal, () -> check(admitted.original, gate, false));
                if (terminal != null) { preserve(terminal, new InterruptedBootstrap(files, returns, true, failure == null, admitted.actualReload)); admitted.result.completeExceptionally(terminal); }
                return null;
            }).whenComplete((value, scheduling) -> {
                if (scheduling != null) completeSchedulingFailure(admitted, files, returns, request, failure, scheduling);
            });
        } catch (RuntimeException | Error scheduling) {
            completeSchedulingFailure(admitted, files, returns, request, failure, scheduling);
        }
    }

    private static void completeSchedulingFailure(Accepted admitted, Object files, List<Integer> returns,
                                                  HostDispatcher.InspectionControl request, Throwable failure, Throwable scheduling) {
        Throwable primary = failure == null ? scheduling : failure;
        preserve(primary, scheduling); preserve(primary, new InterruptedBootstrap(files, returns, true, failure == null, admitted.actualReload));
        admitted.result.completeExceptionally(finish(primary, request::checkpoint));
    }

    private static void requireRoot(Pack pack, Path created, Runnable gate) {
        checked(() -> {
            if (pack.getClass() != Pack.class || created.getFileSystem() != Path.of(".").getFileSystem()) throw invalid();
            int count = 0;
            try (var opened = pack.open()) {
                for (var iterator = opened.iterator(); iterator.hasNext();) {
                    gate.run(); var resources = iterator.next();
                    try (resources) {
                        if (++count != 1 || resources.getClass() != FixedPathPackResources.class
                                || !((Object) resources instanceof FixedPathPackReadAccess access)) throw invalid();
                        List<Path> roots = access.mmmm$rootPaths();
                        if (roots.size() != 1 || !roots.getFirst().toAbsolutePath().normalize().equals(created.toAbsolutePath().normalize())) throw invalid();
                        // Current root metadata only. This does not turn the closed installation handles into a retained identity lease.
                        gate.run(); if (!Files.isSameFile(roots.getFirst(), created)) throw invalid(); gate.run();
                    }
                }
            } catch (IOException failure) {
                var typed = new ContractException("CALIBRATION_BOOTSTRAP_PACK_ROOT_UNAVAILABLE", "The actual installed resource root cannot be observed");
                typed.initCause(failure); throw typed;
            }
            if (count != 1) throw invalid(); return null;
        }, gate);
    }

    @Override public CompletionStage<ObjectNode> poll(HostSession owner, String invocationId, HostDispatcher.InspectionControl request) { return history(owner, invocationId, request); }
    @Override public CompletionStage<ObjectNode> cancel(HostSession owner, String invocationId, HostDispatcher.InspectionControl request) { return history(owner, invocationId, request); }
    private CompletionStage<ObjectNode> history(HostSession owner, String invocationId, HostDispatcher.InspectionControl request) {
        return tasks.submit(() -> {
            Accepted original = accepted; if (original == null) throw invalid();
            Runnable gate = control(owner, original.original.context(), request);
            return checked(() -> {
                gate.run();
                if (!original.original.invocationId().equals(invocationId)
                        || !reservations.containsExact(original.original)) throw invalid();
                return ContractJson.newObject().put("invocationId", original.original.invocationId())
                        .put("status", original.result.isDone() ? "unknown" : "running").put("effects", "unknown");
            }, gate);
        });
    }

    static ObjectNode absenceImage(String targetId, ObjectNode selector) {
        String scope = switch (selector.path("kind").asText()) {
            case "calibration_pack" -> "native_bootstrap_pack_directory_absence";
            case "objective" -> "native_bootstrap_objective_absence";
            case "owned_storage" -> "native_bootstrap_cache_and_backing_absence";
            default -> throw invalid();
        };
        ObjectNode image = ContractJson.newObject().put("format", "mmmm.native.calibration-bootstrap-absence/1")
                .put("targetId", targetId).put("status", "known").put("presence", "absent").put("coverage", "full_target").put("captureScope", scope);
        image.set("selector", selector.deepCopy()); return image;
    }

    static ObjectNode inputSchema() {
        ObjectNode schema = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        schema.putArray("required").add("sourceBundleDigest"); schema.putObject("properties").putObject("sourceBundleDigest").put("type", "string").put("pattern", "^[a-f0-9]{64}$"); return schema;
    }
    static ObjectNode outputSchema() {
        ObjectNode schema = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        schema.putArray("required").add("completionClaim").add("sourceBundleDigest").add("installedFileCount").add("initializedObjectiveCount").add("reloadOutcome");
        ObjectNode properties = schema.putObject("properties"); properties.putObject("completionClaim").put("const", "bootstrap_reload_observation_only");
        properties.putObject("sourceBundleDigest").put("type", "string").put("pattern", "^[a-f0-9]{64}$");
        properties.putObject("installedFileCount").put("const", 48); properties.putObject("initializedObjectiveCount").put("const", 47);
        properties.putObject("reloadOutcome").put("const", "completed"); return schema;
    }

    @Override public void close() { closed.set(true); activated.set(false); }
    private static Set<String> stringSet(JsonNode array) {
        if (!array.isArray() || array.size() > 4096) throw invalid(); Set<String> result = new HashSet<>();
        for (JsonNode value : array) if (!value.isTextual() || !result.add(value.textValue())) throw invalid(); return result;
    }
    private static String text(ObjectNode object, String field) { if (!object.path(field).isTextual()) throw invalid(); return object.path(field).textValue(); }
    private static String sha(ObjectNode object, String field) { String value = text(object, field); if (!value.matches("[a-f0-9]{64}")) throw invalid(); return value; }
    private static void bounded(JsonNode value) {
        if (!withinFrame(value, 0, 0)) throw limit();
    }
    private static boolean withinFrame(JsonNode value, int reservedBytes, int reservedNodes) {
        if (ContractJson.bytes(value).length > Math.min(AnonymousBridge.MAX_FRAME, HostRuntime.MAX_RESULT_BYTES) - reservedBytes) return false;
        record Node(JsonNode value, int depth) { }
        var todo = new ArrayDeque<Node>(); todo.add(new Node(value, 1)); int count = 0;
        while (!todo.isEmpty()) { Node node = todo.removeLast(); if (++count > 4096 - reservedNodes || node.depth() > 64) return false; if (node.value().isContainerNode()) for (JsonNode child : node.value()) todo.add(new Node(child, node.depth() + 1)); }
        return true;
    }
    private static <T> T checked(Supplier<T> action, Runnable post) {
        Throwable primary = null;
        try { return action.get(); } catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally { try { post.run(); } catch (RuntimeException | Error after) { if (primary == null) throw after; preserve(primary, after); } }
    }
    private static Throwable finish(Throwable primary, Runnable post) { try { post.run(); } catch (RuntimeException | Error after) { preserve(primary, after); } return primary; }
    private static void preserve(Throwable primary, Throwable after) { if (primary != after) primary.addSuppressed(after); }
    private static <T> void copy(CompletionStage<T> source, CompletableFuture<T> target) { source.whenComplete((value, failure) -> { if (failure == null) target.complete(value); else target.completeExceptionally(failure); }); }
    private static ContractException invalid() { return new ContractException("CALIBRATION_BOOTSTRAP_UNAPPROVED", "The exact fresh-only bootstrap approval or current native scope is unavailable"); }
    private static ContractException limit() { return new ContractException("CALIBRATION_BOOTSTRAP_LIMIT", "The original bootstrap resource or transport limit was reached"); }
}
