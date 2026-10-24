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
import io.github.daejunnom.mmmm.observer.DefinitionOwnedPackFilesBridge;
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
import java.util.Collection;
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
import net.minecraft.commands.functions.PlainTextFunction;
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
    static final String PACK_PURPOSE = "pack_calibration_bootstrap/1";
    static final String PACK_ACTION_ID = "mmmm:command_execute";
    static final String PACK_COMMAND = "function mmmm_calibration:pack/entry";
    static final String PACK_CASE_TARGET = "calibration-pack-case-pack";
    private static final Set<String> MANIFEST_FIELDS = Set.of("kind", "purpose", "selectionDigest", "hostEpoch",
            "registryGeneration", "runtimeSourceFactsDigest", "suiteDigest", "recipeSha256", "plan", "sourceBundle", "programs");
    private static final Set<String> PROGRAM_FIELDS = Set.of("caseId", "functionId", "objective", "storage", "initializationCommands");
    private static final int MAX_TARGETS = 95, MAX_PACKS = 256;
    private static final int MAX_SOURCE_RECEIPT_BYTES = 64 * 1024;

    /** Routing metadata only. Rust validates the source recipe and issues the retained root kind. */
    enum Purpose {
        NUMERIC47(PURPOSE, "native_calibration_bootstrap_approval/1", ACTION_ID,
                PACK_TARGET, "mmmm-calibration-normative47", 48),
        PACK_CASE(PACK_PURPOSE, "native_pack_calibration_bootstrap_approval/1", PACK_ACTION_ID,
                PACK_CASE_TARGET, "mmmm-calibration-pack-case", 3);
        private final String wire, manifestKind, actionId, targetId, basename;
        private final int entryCount;
        Purpose(String wire, String manifestKind, String actionId, String targetId, String basename, int entryCount) {
            this.wire = wire; this.manifestKind = manifestKind; this.actionId = actionId;
            this.targetId = targetId; this.basename = basename; this.entryCount = entryCount;
        }
        String wire() { return wire; }
        String manifestKind() { return manifestKind; }
        String actionId() { return actionId; }
        String targetId() { return targetId; }
        String basename() { return basename; }
        int entryCount() { return entryCount; }
        static Purpose fromWire(String wire) {
            for (Purpose purpose : values()) if (purpose.wire.equals(wire)) return purpose;
            throw invalid();
        }
    }

    static ObjectNode arguments(Purpose purpose, String bundleDigest) {
        return purpose == Purpose.PACK_CASE ? ContractJson.newObject().put("command", PACK_COMMAND)
                : ContractJson.newObject().put("sourceBundleDigest", bundleDigest);
    }

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
        private void recheck(Runnable current) { checked(() -> { files.checkCurrent(current); if (storage != null) storage.recheck(current); return null; }, current); }
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
        private volatile boolean cancellationRequested;
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
        private final NativeCalibrationPackFiles.SealedFiles sourceFiles;
        private final Purpose purpose;
        private final List<Program> programs;
        private final Set<String> targetIds;
        private final List<NativeLoadedCalibrationSources.ExpectedSource<Identifier>> expectedSources;
        private volatile ResultState result;
        private volatile ReloadState reload = new ReloadState("not_attempted", null);
        private volatile String effectPhase = "accepted";
        private volatile ObjectNode fileFacts;
        private volatile int initializationAttemptedCount;
        private volatile List<Integer> initializationReturns = List.of();
        private volatile DefinitionOwnedPackFilesBridge.RootAnchor reservedRootAnchor;
        private volatile DefinitionOwnedPackFilesBridge.RootAnchor heldRootAnchor;
        private volatile DefinitionOwnedPackFilesBridge.HeldRootReceipt rootRetirement;
        private volatile Throwable rootRetirementFailure;
        private volatile boolean sourceArmAttempted;
        private volatile NativeFunctionLoadObservation sourceObservation;
        private volatile Throwable sourceObservationFailure;

        private Attempt(NativeCalibrationBootstrap bootstrap, Invocation invocation, CompletionStage<ProviderResult> actualResult) {
            owner = bootstrap.server; original = invocation; invocationDigest = ContractJson.digest(invocation.wire());
            bundleDigest = bootstrap.bundleDigest; manifestDigest = bootstrap.manifestDigest;
            sourceFiles = bootstrap.source;
            purpose = bootstrap.purpose;
            gameInstanceId = invocation.context().path("environment").path("gameInstanceId").asText();
            worldId = invocation.context().path("environment").path("worldId").asText();
            programs = bootstrap.programs;
            Set<String> ids = new HashSet<>(); ids.add(purpose.targetId());
            for (Program program : programs) {
                ids.add("calibration-objective-" + program.objective());
                ids.add("calibration-storage-" + ContractJson.sha256(program.storage().getBytes(StandardCharsets.UTF_8)));
            }
            targetIds = Set.copyOf(ids);
            var converter = new FileToIdConverter(Registries.elementsDirPath(ServerFunctionLibrary.TYPE_KEY), ".mcfunction");
            var expected = new ArrayList<NativeLoadedCalibrationSources.ExpectedSource<Identifier>>(47);
            List<String> functionIds = purpose == Purpose.PACK_CASE
                    ? List.of("mmmm_calibration:pack/entry", "mmmm_calibration:pack/dependency")
                    : programs.stream().map(Program::functionId).toList();
            for (String functionId : functionIds) {
                Identifier id = Identifier.parse(functionId);
                String path = "data/mmmm_calibration/function/" + functionId.substring("mmmm_calibration:".length()) + ".mcfunction";
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
        Purpose purpose() { return purpose; }
        NativeCalibrationPackFiles.SealedFiles sourceFiles() { return sourceFiles; }
        DefinitionOwnedPackFilesBridge.RootAnchor rootAnchorForCleanup() { return reservedRootAnchor; }
        DefinitionOwnedPackFilesBridge.RootAnchor heldRootAnchor() { return heldRootAnchor; }
        void requireActualServer(MinecraftServer actual) { if (actual != owner) throw invalid(); }
        synchronized void reserveRootAnchor(DefinitionOwnedPackFilesBridge.RootAnchor locator) {
            Objects.requireNonNull(locator);
            if (reservedRootAnchor != null) throw invalid();
            // Locator ownership only. No native root or publication is claimed.
            reservedRootAnchor = locator;
        }
        synchronized void retainRootAnchor(DefinitionOwnedPackFilesBridge.RootAnchor actual) {
            Objects.requireNonNull(actual);
            if (actual != reservedRootAnchor || heldRootAnchor != null) throw invalid();
            heldRootAnchor = actual; effectPhase = "pack_root_held";
        }
        void retireRoot(MinecraftServer actual, Runnable cleanup) {
            requireActualServer(actual);
            if (reservedRootAnchor == null || retirementConsumed(rootRetirement)) return;
            try { rootRetirement = NativeCalibrationPackFiles.retireRetainedRoot(actual, this, cleanup); }
            catch (RuntimeException | Error failure) {
                if (failure instanceof DefinitionOwnedPackFilesBridge.NativeFailure nativeFailure
                        && nativeFailure.completedHeldReceipt() != null) rootRetirement = nativeFailure.completedHeldReceipt();
                Throwable before = rootRetirementFailure;
                if (before == null) rootRetirementFailure = failure; else preserve(before, failure);
                throw failure;
            }
        }
        void retireForServerStop(MinecraftServer actual, Runnable cleanup) {
            requireActualServer(actual);
            Throwable primary = null;
            try {
                cleanup.run();
                NativeFunctionLoadObservation observed = sourceObservation;
                if (observed != null) observed.retire();
            } catch (RuntimeException | Error failure) { retainSourceFailure(failure); primary = failure; }
            // One failed retirement must not skip the other retained owner.
            try { retireRoot(actual, cleanup); }
            catch (RuntimeException | Error failure) {
                if (primary == null) primary = failure; else preserve(primary, failure);
            }
            if (primary instanceof RuntimeException failure) throw failure;
            if (primary instanceof Error failure) throw failure;
        }
        private synchronized void retainSourceFailure(Throwable actual) {
            if (sourceObservationFailure == null) sourceObservationFailure = actual;
        }
        private void refreshSourceFailure() {
            NativeFunctionLoadObservation observed = sourceObservation;
            if (observed == null) return;
            try {
                var first = observed.firstFailure();
                // The port also retains fresh-call failures. Those belong only
                // to currentFailure, never the historical loader's first cause.
                if (first != null && first.phase() != NativeFunctionLoadObservation.Phase.OBSERVE_CURRENT)
                    retainSourceFailure(first.actualThrowable());
            } catch (RuntimeException | Error failure) { retainSourceFailure(failure); }
        }
        private void armSourceObservation(Collection<String> actualSelection) {
            // Observation is a one-shot diagnostic of the approved original call.
            // Its failure cannot cancel, replace or retry the engine's reload.
            if (sourceArmAttempted) return;
            sourceArmAttempted = true;
            try {
                sourceObservation = NativeFunctionLoadObservation.begin(owner, this, original,
                        sourceFiles, heldRootAnchor, actualSelection);
                refreshSourceFailure();
            } catch (RuntimeException | Error failure) { retainSourceFailure(failure); }
        }
        private static boolean retirementConsumed(DefinitionOwnedPackFilesBridge.HeldRootReceipt actual) {
            return actual != null && Set.of("reference_released", "close_uncertain", "vm_owned").contains(actual.state());
        }
        void requireScope(ObjectNode context) {
            if (!stringSet(context.path("scope").path("externalTargetIds")).containsAll(targetIds)) throw invalid();
        }
        void requireActualOwner(MinecraftServer actual, String actualGame, String actualWorld) {
            if (actual != owner || !gameInstanceId.equals(actualGame) || !worldId.equals(actualWorld)) throw invalid();
        }

        /** A fresh load-only native witness. The historical bootstrap grants no new execution authority. */
        PackRunReadiness packRunReadiness(MinecraftServer actual, ServerLevel actualLevel, HostSession freshOwner,
                                         ObjectNode freshContext, Runnable freshCurrent) {
            requireActualServer(actual);
            return NativeCalibrationStateReader.currentContext(actual, actualLevel, freshOwner, freshContext,
                    freshCurrent::run, (ignored, checkpoint) -> {
                checkpoint.check();
                requireActualOwner(actual, freshContext.path("environment").path("gameInstanceId").asText(),
                        freshContext.path("environment").path("worldId").asText());
                for (String field : Set.of("principalRef", "projectId", "dimension"))
                    if (!original.context().path(field).equals(freshContext.path(field))) throw packRunUnavailable();
                if (purpose != Purpose.PACK_CASE || !"completed".equals(reload.outcome()) || heldRootAnchor == null
                        || sourceObservation == null || sourceObservationFailure != null) throw packRunUnavailable();
                var entry = actual.getFunctions().get(Identifier.parse("mmmm_calibration:pack/entry"))
                        .orElseThrow(NativeCalibrationBootstrap::packRunUnavailable);
                var dependency = actual.getFunctions().get(Identifier.parse("mmmm_calibration:pack/dependency"))
                        .orElseThrow(NativeCalibrationBootstrap::packRunUnavailable);
                if (entry.getClass() != PlainTextFunction.class || dependency.getClass() != PlainTextFunction.class
                        || entry == dependency) throw packRunUnavailable();
                var readiness = new PackRunReadiness(this, actualLevel, (PlainTextFunction<?>) entry,
                        (PlainTextFunction<?>) dependency);
                readiness.checkCurrent(checkpoint::check);
                byte[] originalReceipt = withRetainedPackRoot(actual, sourceFiles.repositoryId(), checkpoint::check,
                        root -> sourceObservation.packRunReadiness(
                                NativeCalibrationPackFiles.freshCurrentRootPort(actual, this, root, checkpoint::check),
                                entry, dependency));
                readiness.retainLoadReceipt(originalReceipt);
                readiness.checkCurrent(checkpoint::check); return readiness;
            });
        }

        /** Plan-create baseline only. No future run Invocation or command result is manufactured. */
        PackRunReadiness packRunInitialReadiness(MinecraftServer actual, ServerLevel actualLevel, HostSession freshOwner,
                ObjectNode freshContext, Runnable freshCurrent, Clock observationClock) {
            Objects.requireNonNull(observationClock);
            return NativeCalibrationStateReader.currentContext(actual, actualLevel, freshOwner, freshContext,
                    freshCurrent::run, (installed, checkpoint) -> {
                if (!stringSet(installed.path("scope").path("externalTargetIds")).contains("calibration-objective-mcalpack"))
                    throw packRunUnavailable();
                PackRunReadiness readiness = packRunReadiness(actual, actualLevel, freshOwner, installed, checkpoint::check);
                readiness.checkCurrent(checkpoint::check);
                long from = Integer.toUnsignedLong(actual.getTickCount());
                ObjectNode raw = NativeTargets.readObjectiveImage(actualLevel, "mcalpack", checkpoint::check);
                if (!"known".equals(raw.path("status").asText()) || !"full_target".equals(raw.path("coverage").asText())
                        || !"absent".equals(raw.path("presence").asText())) throw packRunUnavailable();
                byte[] bytes = ContractJson.canonical(raw);
                if (bytes.length == 0 || bytes.length > NativeCalibrationTargetImages.MAX_TARGET_BYTES) throw limit();
                checkpoint.check(); readiness.checkCurrent(checkpoint::check);
                readiness.retainInitialTarget(installed, bytes, from, Integer.toUnsignedLong(actual.getTickCount()),
                        observationClock.instant().toString());
                readiness.checkCurrent(checkpoint::check); return readiness;
            });
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
            history.put("rootAnchorReserved", reservedRootAnchor != null).put("rootAnchorRecorded", heldRootAnchor != null);
            if (rootRetirement == null) history.putNull("rootRetirement"); else history.set("rootRetirement", heldRootFacts(rootRetirement));
            history.set("rootRetirementFailure", throwable(rootRetirementFailure));
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
                ObjectNode observation = response.putObject("observation").put("format", "mmmm.native.calibration-bootstrap-observation/2")
                        .put("observedFromTick", Long.toString(from)).put("observedToTick", Long.toString(from));
                SourceTrace trace = new SourceTrace(sourceArmAttempted);
                refreshSourceFailure();
                NativeFunctionLoadObservation sourceCapture = sourceObservation;
                if (sourceCapture != null) {
                    try { trace.historical(sourceCapture.opaqueReceipt()); }
                    catch (RuntimeException | Error failure) { retainSourceFailure(failure); }
                }
                ObjectNode pack = observation.putObject("pack").put("status", "unknown").put("reason", "retained_root_not_published")
                        .put("identityContinuity", "unproven").put("currentBytes", "not_observed").put("fullPackMembership", "unproven");
                pack.putNull("retainedRoot"); pack.putNull("failure");
                if (heldRootAnchor != null) {
                    try {
                        var retained = withRetainedPackRoot(actual, sourceFiles.repositoryId(), current, root -> {
                            var facts = NativeCalibrationPackFiles.observeRetainedRoot(actual, this, root, current);
                            if (sourceCapture != null) {
                                try {
                                    var port = NativeCalibrationPackFiles.freshCurrentRootPort(actual, this, root, current);
                                    trace.current(sourceCapture.observeCurrent(port));
                                } catch (RuntimeException | Error failure) {
                                    // This call's failure never overwrites the original first source cause.
                                    trace.currentFailure = failure;
                                }
                            }
                            return facts;
                        });
                        pack.set("retainedRoot", heldRootFacts(retained));
                        pack.put("status", "observed").put("reason", "native_retained_root_identity_only");
                        pack.put("identityContinuity", retained.identity());
                    } catch (RuntimeException failure) {
                        if (failure instanceof DefinitionOwnedPackFilesBridge.NativeFailure nativeFailure
                                && nativeFailure.completedHeldReceipt() != null) pack.set("retainedRoot", heldRootFacts(nativeFailure.completedHeldReceipt()));
                        pack.put("reason", "native_retained_root_observation_failed");
                        pack.set("failure", observedFailure(failure, current));
                    }
                }
                refreshSourceFailure();
                // Attach before targets: their existing whole-response budget
                // includes the opaque receipt and both bounded failure graphs.
                observation.set("loadedSourceTrace", sourceTraceWire(trace.attempted, trace.origin,
                        trace.receipt, sourceObservationFailure, trace.currentFailure));
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
                    // PACK's command/marker readback has not been implemented.
                    // An empty numeric target loop is not known PACK coverage.
                    boolean known = purpose == Purpose.NUMERIC47; int bytes = 0;
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

    /** Actual object capability issued only by the retained native load observation above. */
    static final class PackRunReadiness {
        private final Attempt attempt;
        private final ServerLevel level;
        private final Object resources, functions, repository;
        private final PlainTextFunction<?> entry, dependency;
        private final List<?> entryEntries, dependencyEntries;
        private byte[] loadReceipt;
        private InitialTarget initialTarget;
        private record InitialTarget(ObjectNode context, byte[] bytes, long from, long to, String observedAt) { }
        private PackRunReadiness(Attempt actual, ServerLevel actualLevel, PlainTextFunction<?> actualEntry,
                                 PlainTextFunction<?> actualDependency) {
            attempt = actual; level = actualLevel;
            resources = actual.owner.getResourceManager(); functions = actual.owner.getFunctions();
            repository = actual.owner.getPackRepository(); entry = actualEntry; dependency = actualDependency;
            entryEntries = actualEntry.entries(); dependencyEntries = actualDependency.entries();
            if (entryEntries == null || dependencyEntries == null) throw packRunUnavailable();
        }
        private void retainLoadReceipt(byte[] raw) {
            if (loadReceipt != null) throw packRunUnavailable();
            loadReceipt = NativeFunctionLoadObservation.requirePackReceipt(raw, 47);
        }
        byte[] receipt() {
            if (loadReceipt == null) throw packRunUnavailable(); return loadReceipt.clone();
        }
        private void retainInitialTarget(ObjectNode actualContext, byte[] actualBytes, long from, long to, String observedAt) {
            if (initialTarget != null || from < 0 || to < from) throw packRunUnavailable();
            initialTarget = new InitialTarget(actualContext.deepCopy(), actualBytes.clone(), from, to, observedAt);
        }
        /** Transports one actual absent-objective baseline. It is never a command-settlement observation. */
        ObjectNode targetImages(ObjectNode actualSourceFacts, String actualHostArtifactDigest,
                                String actualRegistryGeneration, Clock observationClock) {
            Objects.requireNonNull(observationClock);
            ObjectNode sourceFacts = Objects.requireNonNull(actualSourceFacts).deepCopy();
            InitialTarget actual = initialTarget;
            if (actual == null || actualHostArtifactDigest == null || !actualHostArtifactDigest.matches("[a-f0-9]{64}")
                    || actualRegistryGeneration == null || !actualRegistryGeneration.matches("(0|[1-9][0-9]{0,19})")
                    || !actual.context().path("environment").equals(sourceFacts.path("environment"))
                    || !actualRegistryGeneration.equals(sourceFacts.path("registryGeneration").asText())) throw packRunUnavailable();
            String sourceFactsDigest = NativeProfileAdmission.sourceDigest(sourceFacts);
            ObjectNode value = ContractJson.newObject().put("format", NativePackCalibrationSource.TARGET_IMAGES_FORMAT)
                    .put("protocolVersion", ContractJson.VERSION).put("contextId", actual.context().path("contextId").asText())
                    .put("contextDigest", actual.context().path("contextDigest").asText())
                    .put("runtimeSourceFactsDigest", sourceFactsDigest).put("hostArtifactDigest", actualHostArtifactDigest)
                    .put("registryGeneration", actualRegistryGeneration)
                    .put("observedFromTick", Long.toString(actual.from())).put("observedToTick", Long.toString(actual.to()))
                    .put("observedAt", actual.observedAt());
            value.set("environment", actual.context().path("environment").deepCopy());
            value.putArray("targets").addObject().put("targetId", "calibration-objective-mcalpack")
                    .put("rawBytesHex", java.util.HexFormat.of().formatHex(actual.bytes()))
                    .put("rawSha256", ContractJson.sha256(actual.bytes()));
            ObjectNode observation = value.putObject("commandObservation").put("commandReturnObserved", false)
                    .put("singleCallbackObserved", false).put("queueTerminalObserved", false)
                    .put("actualTaskTerminalObserved", false).put("terminationConfirmed", false).put("furtherEffectsPossible", true);
            observation.putNull("continuationPending");
            NativePackCalibrationSource.bounded(value); return value;
        }
        PlainTextFunction<?> entryFunction() { return entry; }
        PlainTextFunction<?> dependencyFunction() { return dependency; }
        List<?> entryEntries() { return entryEntries; }
        List<?> dependencyEntries() { return dependencyEntries; }
        void checkCurrent(Runnable freshCurrent) {
            Objects.requireNonNull(freshCurrent).run(); MinecraftServer actual = attempt.owner;
            if (!actual.isSameThread() || level.getServer() != actual || actual.getLevel(level.dimension()) != level
                    || actual.getResourceManager() != resources || actual.getFunctions() != functions
                    || actual.getPackRepository() != repository || attempt.purpose != Purpose.PACK_CASE
                    || attempt.heldRootAnchor == null || attempt.sourceObservation == null
                    || actual.getFunctions().get(Identifier.parse("mmmm_calibration:pack/entry")).orElse(null) != entry
                    || actual.getFunctions().get(Identifier.parse("mmmm_calibration:pack/dependency")).orElse(null) != dependency
                    || entry.entries() != entryEntries || dependency.entries() != dependencyEntries) throw packRunUnavailable();
            freshCurrent.run();
        }
        /** Fresh current checks bracket each original native event; no original bootstrap callback is retained. */
        byte[] requireRun(Invocation actualRun, int eventKind, Object owner, Object callee, Object source, Object context,
                          Object parent, Object child, List<?> entries, Object provider, Object actualEntry,
                          Object queueEntry, Object action, Throwable failure, byte[] rawFacts, Runnable freshCurrent) {
            Objects.requireNonNull(actualRun); checkCurrent(freshCurrent);
            if (loadReceipt == null || !"pack-entry".equals(actualRun.stepId())
                    || !PACK_ACTION_ID.equals(actualRun.actionId())
                    || !arguments(Purpose.PACK_CASE, attempt.bundleDigest).equals(actualRun.arguments())
                    || actualRun == attempt.original || actualRun.invocationId().equals(attempt.original.invocationId())
                    || actualRun.operationId().equals(attempt.original.operationId())) throw packRunUnavailable();
            return checked(() -> withRetainedPackRoot(attempt.owner, attempt.sourceFiles.repositoryId(), freshCurrent,
                    root -> attempt.sourceObservation.packRunObservation(
                            NativeCalibrationPackFiles.freshCurrentRootPort(attempt.owner, attempt, root, freshCurrent),
                            entry, dependency, actualRun, eventKind, owner, callee, source, context, parent, child,
                            entries, provider, actualEntry, queueEntry, action, failure, rawFacts)),
                    () -> checkCurrent(freshCurrent));
        }
    }

    private static ContractException packRunUnavailable() {
        return new ContractException("CAPABILITY_UNAVAILABLE", "The actual current PACK load or run boundary is unavailable");
    }

    private static ObjectNode heldRootFacts(DefinitionOwnedPackFilesBridge.HeldRootReceipt actual) {
        return ContractJson.newObject().put("operation", actual.operation()).put("state", actual.state())
                .put("evidenceGrade", actual.evidenceGrade()).put("identity", actual.identity()).put("pins", actual.pins())
                .put("closed", actual.closed()).put("shared", actual.shared()).put("uncertain", actual.uncertain());
    }

    private static <T> T withRetainedPackRoot(MinecraftServer server, String repositoryId, Runnable current, Function<Path, T> observe) {
        return checked(() -> {
            current.run(); Pack selected = null; int count = 0;
            for (Pack pack : server.getPackRepository().getAvailablePacks()) {
                current.run(); if (++count > MAX_PACKS) throw limit();
                if (pack.getId().equals(repositoryId)) {
                    if (selected != null) throw invalid(); selected = pack;
                }
            }
            if (selected == null) throw new ContractException("CALIBRATION_BOOTSTRAP_PACK_UNAVAILABLE", "The actual repository did not expose the original pack");
            return withPackRoot(selected, current, observe);
        }, current);
    }

    private static final class SourceTrace {
        private final boolean attempted;
        private String origin = "none";
        private byte[] receipt;
        private Throwable currentFailure;
        private SourceTrace(boolean attempted) { this.attempted = attempted; }
        private void historical(byte[] raw) {
            if (raw.length == 0) return;
            requireSourceReceipt(raw); receipt = raw; origin = "historical_only";
        }
        private void current(byte[] raw) {
            requireSourceReceipt(raw); receipt = raw; origin = "current_call_return";
        }
    }

    /** Descriptive transport only. Java never decodes native facts or issues source authority. */
    static ObjectNode sourceTraceWire(boolean attempted, String origin, byte[] receipt,
                                      Throwable firstFailure, Throwable currentFailure) {
        if (!Set.of("none", "historical_only", "current_call_return").contains(origin)
                || (receipt == null) != "none".equals(origin)
                || ("current_call_return".equals(origin) && currentFailure != null)
                || (!attempted && (receipt != null || firstFailure != null || currentFailure != null))) throw limit();
        ObjectNode wire = ContractJson.newObject().put("format", "mmmm.native.calibration-loaded-source-trace/1")
                .put("armAttempted", attempted).put("receiptOrigin", origin);
        if (receipt == null) wire.putNull("receiptBytesHex");
        else { requireSourceReceipt(receipt); wire.put("receiptBytesHex", java.util.HexFormat.of().formatHex(receipt)); }
        wire.set("failure", throwable(firstFailure)); wire.set("currentFailure", throwable(currentFailure));
        return wire;
    }
    private static void requireSourceReceipt(byte[] raw) {
        if (raw == null || raw.length == 0 || raw.length > MAX_SOURCE_RECEIPT_BYTES) throw limit();
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
            retained = withinFrame(response, 32 * 1024 + 10 - actualTick.length(), 512);
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
        else if (actual instanceof DefinitionOwnedPackFilesBridge.NativeFailure nativeFailure) {
            node.put("code", nativeFailure.code()).put("effectsMayExist", nativeFailure.effectsMayExist());
            if (nativeFailure.nativeError() != null) node.put("nativeError", nativeFailure.nativeError());
            var create = nativeFailure.nativeCreate();
            if (create != null) {
                ObjectNode observed = node.putObject("nativeCreate").put("ntStatus", create.ntStatus()).put("completionStatus", create.completionStatus())
                        .put("closeNativeError", create.closeNativeError());
                if (create.information() == null) observed.putNull("informationUnsigned");
                else observed.put("informationUnsigned", Long.toUnsignedString(create.information()));
            }
            var lifetime = nativeFailure.nativeLifetime();
            if (lifetime != null) node.putObject("nativeLifetime").put("kind", lifetime.kind()).put("operation", lifetime.operation())
                    .put("status", lifetime.status()).put("nativeCode", lifetime.nativeCode());
            var close = nativeFailure.retainedClose();
            if (close != null) node.putObject("retainedClose").put("stage", close.stage()).put("pin", close.pin());
        }
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
    private final Purpose purpose;
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
        purpose = Purpose.fromWire(text(manifest, "purpose"));
        if (!purpose.manifestKind().equals(text(manifest, "kind"))
                || !session.epoch().equals(text(manifest, "hostEpoch")) || session.verifiedWriteProfile()) throw invalid();
        for (String field : Set.of("selectionDigest", "runtimeSourceFactsDigest", "suiteDigest", "recipeSha256")) sha(manifest, field);
        if (!text(manifest, "suiteDigest").equals(text(manifest, "recipeSha256"))
                || !text(manifest, "registryGeneration").matches("[1-9][0-9]{0,18}")) throw invalid();
        ObjectNode inner = ContractJson.object(manifest.path("plan"));
        if (!inner.path("steps").isArray() || inner.path("steps").size() != 1
                || !inner.path("nativeExecutions").isArray() || !inner.path("nativeExecutions").isEmpty()
                || !inner.path("contextPins").isArray() || inner.path("contextPins").size() != 1) throw invalid();
        plan = new NativePlanApproval(contracts, inner, clock); step = ContractJson.object(inner.path("steps").get(0)).deepCopy();
        if (!purpose.actionId().equals(text(step, "actionId"))) throw invalid();
        contextId = text(step, "contextId");
        source = NativeCalibrationPackFiles.SealedFiles.fromPrivateRustBundle(ContractJson.object(manifest.path("sourceBundle")), purpose);
        bundleDigest = sha(ContractJson.object(manifest.path("sourceBundle")), "bundleDigest");
        ObjectNode arguments = arguments(purpose, bundleDigest);
        if (!ContractJson.digest(arguments).equals(text(step, "argumentsDigest"))) throw invalid();
        if (!manifest.path("programs").isArray() || manifest.path("programs").size() != (purpose == Purpose.NUMERIC47 ? 47 : 0)) throw invalid();
        List<Program> parsed = new ArrayList<>(); Set<String> cases = new HashSet<>(), functions = new HashSet<>(), targets = new HashSet<>();
        targets.add(purpose.targetId());
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
        int targetCount = purpose == Purpose.NUMERIC47 ? MAX_TARGETS : 1;
        if (targets.size() != targetCount || !stringSet(step.path("resourcesRead")).equals(targets)
                || !stringSet(step.path("resourcesWritten")).equals(targets)) throw invalid();
        Set<String> conditions = new HashSet<>();
        if (!step.path("preconditions").isArray() || step.path("preconditions").size() != targetCount) throw invalid();
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
    Purpose purpose() { return purpose; }
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
        if (!arguments(purpose, bundleDigest).equals(original.arguments())) throw invalid();
        current.check(session, original.context(), control, sources); control.run();
    }

    private Prepared observe(ObjectNode context, Runnable control) {
        control.run(); long fromTick = Integer.toUnsignedLong(server.getTickCount());
        ServerLevel level = levels.apply(context.path("dimension").asText());
        if (level == null || level.getServer() != server || server.getLevel(level.dimension()) != level) throw invalid();
        var files = NativeCalibrationPackFiles.prepare(server, level, session, context, source, control);
        var state = purpose == Purpose.NUMERIC47
                ? NativeCalibrationStorageAcquisition.prepare(server, level, session, context, programs, control) : null;
        ObjectNode images = ContractJson.newObject().put("format", "mmmm.native.calibration-target-images/1")
                .put("protocolVersion", ContractJson.VERSION).put("contextId", contextId).put("contextDigest", context.path("contextDigest").asText())
                .put("runtimeSourceFactsDigest", runtimeSourceFactsDigest()).put("hostArtifactDigest", step.path("implementationDigest").asText())
                .put("registryGeneration", registryGeneration()).put("observedFromTick", Long.toString(fromTick))
                .put("observedToTick", Long.toString(Integer.toUnsignedLong(server.getTickCount()))).put("observedAt", Instant.now().toString());
        images.set("environment", context.path("environment").deepCopy()); ArrayNode targetRows = images.putArray("targets");
        targetRows.add(files.beforeTargets()); if (state != null) state.beforeTargets().forEach(targetRows::add);
        if (targetRows.size() != (purpose == Purpose.NUMERIC47 ? MAX_TARGETS : 1)) throw invalid();
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
            var installed = prepared.files.execute(admitted.attempt, gate); files = installed;
            admitted.attempt.fileFacts = installed.toWire(); admitted.attempt.effectPhase = "pack_created";
            if (purpose == Purpose.NUMERIC47) {
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
            var actualSelection = List.copyOf(selection);
            check(admitted.original, gate, true);
            admitted.attempt.armSourceObservation(actualSelection);
            // The original gate still owns deadline/cancellation after observer work.
            check(admitted.original, gate, true); requested = true; admitted.attempt.startReload();
            // Reload is the final effect. Its native START hook retires this route; no next write follows it.
            var reload = server.reloadResources(actualSelection);
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
                        if (purpose == Purpose.PACK_CASE) {
                            if (!admitted.cancellationRequested) admitted.attempt.effectPhase = "pack_reload_observed_command_not_dispatched";
                            // The original action is synchronous and has no job
                            // callbacks. Preserve this slice's actual effects
                            // without inventing a job or command completion.
                            throw new ContractException("CAPABILITY_UNAVAILABLE",
                                    "The original PACK command remains undispatched after the source reload slice");
                        } else {
                            ObjectNode output = ContractJson.newObject().put("completionClaim", "bootstrap_reload_observation_only")
                                    .put("sourceBundleDigest", bundleDigest).put("installedFileCount", 48)
                                    .put("initializedObjectiveCount", returns.size()).put("reloadOutcome", "completed");
                            admitted.result.complete(ProviderResult.complete(contracts, output, "unknown"));
                        }
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
        if (created.getFileSystem() != Path.of(".").getFileSystem()) throw invalid();
        withPackRoot(pack, gate, root -> {
            if (!root.toAbsolutePath().normalize().equals(created.toAbsolutePath().normalize())) throw invalid();
            // This lexical/current-file check alone issues no retained identity
            // or loaded-source causality claim. Native owns the retained root.
            try { gate.run(); if (!Files.isSameFile(root, created)) throw invalid(); gate.run(); }
            catch (IOException failure) { throw rootUnavailable(failure); }
            return null;
        });
    }

    private static <T> T withPackRoot(Pack pack, Runnable gate, Function<Path, T> observe) {
        return checked(() -> {
            if (pack.getClass() != Pack.class) throw invalid();
            int count = 0;
            T observed = null;
            try (var opened = pack.open()) {
                for (var iterator = opened.iterator(); iterator.hasNext();) {
                    gate.run(); var resources = iterator.next();
                    try (resources) {
                        if (++count != 1 || resources.getClass() != FixedPathPackResources.class
                                || !((Object) resources instanceof FixedPathPackReadAccess access)) throw invalid();
                        List<Path> roots = access.mmmm$rootPaths();
                        if (roots.size() != 1 || roots.getFirst().getFileSystem() != Path.of(".").getFileSystem()) throw invalid();
                        gate.run(); observed = observe.apply(roots.getFirst()); gate.run();
                    }
                }
            }
            if (count != 1) throw invalid(); return observed;
        }, gate);
    }
    private static ContractException rootUnavailable(IOException failure) {
        var typed = new ContractException("CALIBRATION_BOOTSTRAP_PACK_ROOT_UNAVAILABLE", "The actual installed resource root cannot be observed");
        typed.initCause(failure); return typed;
    }

    @Override public CompletionStage<ObjectNode> poll(HostSession owner, String invocationId, HostDispatcher.InspectionControl request) { return history(owner, invocationId, request, false); }
    @Override public CompletionStage<ObjectNode> cancel(HostSession owner, String invocationId, HostDispatcher.InspectionControl request) { return history(owner, invocationId, request, true); }
    private CompletionStage<ObjectNode> history(HostSession owner, String invocationId, HostDispatcher.InspectionControl request, boolean cancel) {
        return tasks.submit(() -> {
            Accepted original = accepted; if (original == null) throw invalid();
            Runnable gate = control(owner, original.original.context(), request);
            return checked(() -> {
                gate.run();
                if (!original.original.invocationId().equals(invocationId)
                        || !reservations.containsExact(original.original)) throw invalid();
                if (cancel && purpose == Purpose.PACK_CASE) {
                    original.cancellationRequested = true;
                    original.attempt.effectPhase = "pack_command_cancelled_before_dispatch";
                }
                ObjectNode state = ContractJson.newObject().put("invocationId", original.original.invocationId())
                        .put("status", purpose == Purpose.PACK_CASE ? "unknown"
                                : original.result.isDone() ? "unknown" : "running")
                        .put("effects", "unknown");
                // This slice has issued no command result or job. A cancelled
                // reply cannot prove an already started engine reload stopped.
                if (purpose == Purpose.PACK_CASE) state.put("furtherEffectsPossible", true).put("providerCompleted", false)
                        .put("cancellationRequested", original.cancellationRequested).put("terminationConfirmed", false);
                return state;
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
