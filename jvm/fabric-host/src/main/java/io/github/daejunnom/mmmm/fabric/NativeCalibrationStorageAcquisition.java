package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.fabric.mixin.CommandStorageBootstrapAccess;
import io.github.daejunnom.mmmm.fabric.mixin.CommandStorageContainerBootstrapAccess;
import io.github.daejunnom.mmmm.fabric.mixin.CommandStorageContainerCacheAccessor;
import io.github.daejunnom.mmmm.fabric.mixin.SavedDataStorageBootstrapAccess;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.saveddata.SavedData;
import net.minecraft.world.level.saveddata.SavedDataType;
import net.minecraft.world.level.storage.CommandStorage;
import net.minecraft.world.level.storage.SavedDataStorage;
import net.minecraft.world.scores.Scoreboard;

/** Fresh owned bootstrap only. No native disk loader, synthesized NBT root, save or approval is issued. */
final class NativeCalibrationStorageAcquisition {
    private static final String NAMESPACE = "mmmm";
    private static final String CONTAINER = "net.minecraft.world.level.storage.CommandStorage$Container";
    private static final int CASE_COUNT = 47;
    private static final int MAX_MEMBERS = 4096;
    private static final int MAX_EVIDENCE_BYTES = 256 * 1024;
    private NativeCalibrationStorageAcquisition() { }
    @FunctionalInterface private interface CurrentRead<T> { T read(NativeCalibrationStateReader.Checkpoint checkpoint); }

    /** Only prepare's actual native/cache/backing observations construct this phase-local identity owner. */
    static final class Prepared {
        private final MinecraftServer server;
        private final ServerLevel level;
        private final HostSession owner;
        private final ObjectNode context;
        private final List<NativeCalibrationBootstrap.Program> programs;
        private final NativeView view;
        private final CacheEntry beforeCache;
        private final NativeCalibrationPackFiles.AbsentStorage backing;
        private final ArrayNode beforeTargets;
        private final ObjectNode evidence;
        private boolean attempted;
        private SavedData acquired;
        private Map<String, CompoundTag> acquiredContents;

        private Prepared(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode context,
                         List<NativeCalibrationBootstrap.Program> programs, NativeView view, CacheEntry beforeCache,
                         NativeCalibrationPackFiles.AbsentStorage backing, ArrayNode beforeTargets, ObjectNode evidence) {
            this.server = server; this.level = level; this.owner = owner; this.context = context.deepCopy();
            this.programs = List.copyOf(programs); this.view = view; this.beforeCache = beforeCache;
            this.backing = backing; this.beforeTargets = beforeTargets.deepCopy(); this.evidence = evidence.deepCopy();
        }

        /** Immutable historical predicate observations; callers persist these exact bytes in the common Store. */
        ArrayNode beforeTargets() { return beforeTargets.deepCopy(); }
        ObjectNode evidence() { return evidence.deepCopy(); }

        /** The original phase control is borrowed per call and is never retained. */
        void recheck(Runnable original) {
            current(original, checkpoint -> {
                view.checkCurrent(); requireScope(context, programs, checkpoint);
                if (!attempted) {
                    requireSameBefore(view, beforeCache, checkpoint);
                    requireObjectivesAbsent(level, view.scoreboard, programs, checkpoint, null);
                } else {
                    requireAcquired(checkpoint);
                }
                backing.recheck(checkpoint::check); checkpoint.check(); return null;
            });
        }

        /** Called only by the purpose owner after its original common durable intent and admission. */
        void acquire(Runnable original) {
            current(original, checkpoint -> {
                if (attempted) throw changed();
                view.checkCurrent(); requireScope(context, programs, checkpoint);
                requireSameBefore(view, beforeCache, checkpoint);
                requireObjectivesAbsent(level, view.scoreboard, programs, checkpoint, null);
                backing.recheck(checkpoint::check); checkpoint.check();
                attempted = true;
                // This supplier comes only from the actual native static Container.type method.
                // A same-ID SavedDataType supplied by a caller is never substituted here.
                SavedData created = Objects.requireNonNull(view.type.constructor().get());
                Map<String, CompoundTag> contents = containerContents(created);
                if (!contents.isEmpty()) throw changed();
                checkpoint.check(); view.checkCurrent();
                requireSameBefore(view, beforeCache, checkpoint); backing.recheck(checkpoint::check);
                Optional<SavedData> previous = view.cache.put(view.type, Optional.of(created));
                if (previous != beforeCache.value) throw changed();
                checkpoint.check(); view.checkCurrent();
                if (view.namespaces.containsKey(NAMESPACE)) throw changed();
                Object old = view.namespaces.put(NAMESPACE, created);
                if (old != null) throw changed();
                acquired = created; acquiredContents = contents;
                requireAcquired(checkpoint); backing.recheck(checkpoint::check); checkpoint.check(); return null;
            });
        }

        private void requireAcquired(NativeCalibrationStateReader.Checkpoint checkpoint) {
            view.checkCurrent(); checkpoint.check();
            if (acquired == null || acquiredContents == null || view.namespaces.get(NAMESPACE) != acquired
                    || containerContents(acquired) != acquiredContents || !acquiredContents.isEmpty()) throw changed();
            CacheEntry current = inspectCache(view, checkpoint);
            SavedDataType<?> expectedKey = beforeCache.key == null ? view.type : beforeCache.key;
            if (current.key != expectedKey || current.value == null || current.value.orElse(null) != acquired) throw changed();
            checkpoint.check();
        }

        private <T> T current(Runnable original, CurrentRead<T> read) {
            Objects.requireNonNull(original);
            return NativeCalibrationStateReader.currentContext(server, level, owner, context, original::run,
                    (ignored, checkpoint) -> {
                        NativeCalibrationStateReader.Checkpoint live = () -> {
                            checkpoint.check(); view.checkCurrent(); checkpoint.check();
                        };
                        return NativeCalibrationStateReader.checked(() -> read.read(live), () -> {
                            live.check(); backing.recheck(live::check); live.check();
                        });
                    });
        }
    }

    static Prepared prepare(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode supplied,
                            List<NativeCalibrationBootstrap.Program> originalPrograms, Runnable original) {
        Objects.requireNonNull(originalPrograms); Objects.requireNonNull(original);
        if (originalPrograms.size() != CASE_COUNT) throw unsupported();
        List<NativeCalibrationBootstrap.Program> programs = List.copyOf(originalPrograms);
        return NativeCalibrationStateReader.currentContext(server, level, owner, supplied, original::run, (context, checkpoint) -> {
            requireScope(context, programs, checkpoint);
            NativeView view = new NativeView(server, level);
            view.checkCurrent();
            CacheEntry cache = inspectCache(view, checkpoint);
            if (view.namespaces.containsKey(NAMESPACE) || (cache.value != null && cache.value.isPresent())) throw unsupported();
            NativeCalibrationPackFiles.AbsentStorage backing = NativeCalibrationPackFiles.prepareStorageAbsence(
                    server, level, owner, context, view.dataFolder, view.dataFile, () -> {
                        // The world-root native walk borrows this exact actual
                        // storage/type/cache identity check at every checkpoint.
                        checkpoint.check(); view.checkCurrent(); checkpoint.check();
                    });
            return NativeCalibrationStateReader.checked(() -> {
            ArrayNode objectiveEvidence = ContractJson.newObject().putArray("images");
            requireObjectivesAbsent(level, view.scoreboard, programs, checkpoint, objectiveEvidence);
            backing.recheck(checkpoint::check); requireSameBefore(view, cache, checkpoint);
            ArrayNode targets = ContractJson.newObject().putArray("targets");
            for (var program : programs) {
                checkpoint.check();
                appendTarget(targets, objectiveId(program), NativeCalibrationBootstrap.absenceImage(objectiveId(program),
                        ContractJson.newObject().put("kind", "objective").put("objective", program.objective())));
                ObjectNode selector = ContractJson.newObject().put("kind", "owned_storage").put("storage", program.storage());
                selector.putArray("ownedSubtrees").add("inputs").add("invocation");
                appendTarget(targets, storageId(program), NativeCalibrationBootstrap.absenceImage(storageId(program), selector));
            }
            ObjectNode evidence = ContractJson.newObject().put("format", "mmmm.native.calibration-bootstrap-state-observation/1")
                    .put("namespace", NAMESPACE).put("cacheBefore", cache.key == null ? "entry_absent" : "negative_entry")
                    .put("nativeTypeId", view.type.id().toString());
            evidence.set("nativeObjectiveImages", objectiveEvidence); evidence.set("storageBacking", backing.facts());
            if (ContractJson.canonical(evidence).length > MAX_EVIDENCE_BYTES) throw limit();
            Prepared prepared = new Prepared(server, level, owner, context, programs, view, cache, backing, targets, evidence);
            prepared.recheck(checkpoint::check); checkpoint.check(); return prepared;
            }, () -> {
                checkpoint.check(); view.checkCurrent(); backing.recheck(checkpoint::check); checkpoint.check();
            });
        });
    }

    private static void appendTarget(ArrayNode targets, String targetId, ObjectNode image) {
        byte[] bytes = ContractJson.canonical(image);
        targets.addObject().put("targetId", targetId).put("rawBytesHex", HexFormat.of().formatHex(bytes))
                .put("rawSha256", ContractJson.sha256(bytes));
    }

    private static void requireObjectivesAbsent(ServerLevel level, Scoreboard scoreboard,
                                                List<NativeCalibrationBootstrap.Program> programs,
                                                NativeCalibrationStateReader.Checkpoint checkpoint, ArrayNode evidence) {
        if (level.getScoreboard() != scoreboard) throw changed();
        for (var program : programs) {
            checkpoint.check();
            if (scoreboard.getObjective(program.objective()) != null) throw unsupported();
            ObjectNode raw = NativeTargets.readObjectiveImage(level, program.objective(), checkpoint::check);
            if (!"mmmm.native.target/1".equals(raw.path("format").asText())
                    || !"objective".equals(raw.path("selector").path("kind").asText())
                    || !program.objective().equals(raw.path("selector").path("objective").asText())
                    || !"known".equals(raw.path("status").asText()) || !"absent".equals(raw.path("presence").asText())
                    || !"full_target".equals(raw.path("coverage").asText())
                    || !"native_objective_and_all_scores".equals(raw.path("captureScope").asText())
                    || scoreboard.getObjective(program.objective()) != null || level.getScoreboard() != scoreboard) throw changed();
            if (evidence != null) {
                byte[] bytes = ContractJson.canonical(raw);
                evidence.addObject().put("targetId", objectiveId(program)).put("rawBytesHex", HexFormat.of().formatHex(bytes))
                        .put("rawSha256", ContractJson.sha256(bytes));
            }
            checkpoint.check();
        }
    }

    private static void requireSameBefore(NativeView view, CacheEntry before, NativeCalibrationStateReader.Checkpoint checkpoint) {
        view.checkCurrent(); checkpoint.check();
        if (view.namespaces.containsKey(NAMESPACE)) throw changed();
        CacheEntry current = inspectCache(view, checkpoint);
        if (current.key != before.key || current.value != before.value
                || (current.value != null && current.value.isPresent())) throw changed();
        checkpoint.check();
    }

    private record CacheEntry(SavedDataType<?> key, Optional<SavedData> value) { }

    private static CacheEntry inspectCache(NativeView view, NativeCalibrationStateReader.Checkpoint checkpoint) {
        view.checkCurrent();
        if (view.cache.size() > MAX_MEMBERS || view.namespaces.size() > MAX_MEMBERS) throw limit();
        SavedDataType<?> selected = null; Optional<SavedData> selectedValue = null; int count = 0, size = view.cache.size();
        for (var entry : view.cache.entrySet()) {
            checkpoint.check(); if (++count > MAX_MEMBERS) throw limit();
            SavedDataType<?> key = entry.getKey(); Optional<SavedData> value = entry.getValue();
            if (key == null || key.getClass() != SavedDataType.class || key.id() == null || value == null) throw changed();
            if (key.id().equals(view.type.id())) {
                if (selected != null || key.constructor() != view.type.constructor() || key.codec() != view.type.codec()
                        || key.dataFixType() != view.type.dataFixType()) throw unsupported();
                selected = key; selectedValue = value;
            }
            if (view.cache.get(key) != value) throw changed();
        }
        if (count != size || view.cache.size() != size) throw changed();
        view.checkCurrent(); checkpoint.check(); return new CacheEntry(selected, selectedValue);
    }

    private static Map<String, CompoundTag> containerContents(SavedData container) {
        if (container == null || !CONTAINER.equals(container.getClass().getName())
                || container.getClass().getClassLoader() != CommandStorage.class.getClassLoader()
                || !(container instanceof CommandStorageContainerCacheAccessor access)) throw unsupported();
        var actual = container.getClass().getProtectionDomain().getCodeSource();
        var admitted = CommandStorage.class.getProtectionDomain().getCodeSource();
        if (actual == null || admitted == null || !actual.getLocation().equals(admitted.getLocation())) throw unsupported();
        Map<String, CompoundTag> contents = access.mmmm$storage();
        if (contents == null || contents.size() > MAX_MEMBERS) throw unsupported();
        return contents;
    }

    private static final class NativeView {
        private final MinecraftServer server;
        private final ServerLevel level;
        private final Scoreboard scoreboard;
        private final CommandStorage storage;
        private final CommandStorageBootstrapAccess storageAccess;
        private final SavedDataStorage savedData;
        private final SavedDataStorageBootstrapAccess savedAccess;
        private final Map<String, Object> namespaces;
        private final Map<SavedDataType<?>, Optional<SavedData>> cache;
        private final Path dataFolder, dataFile;
        private final SavedDataType<?> type;
        private NativeView(MinecraftServer server, ServerLevel level) {
            this.server = server; this.level = level; scoreboard = level.getScoreboard(); storage = server.getCommandStorage();
            if (storage == null || storage.getClass() != CommandStorage.class
                    || !(storage instanceof CommandStorageBootstrapAccess access)) throw unsupported();
            storageAccess = access; namespaces = access.mmmm$bootstrapNamespaces(); savedData = access.mmmm$bootstrapSavedDataStorage();
            if (namespaces == null || savedData == null || savedData.getClass() != SavedDataStorage.class
                    || !(savedData instanceof SavedDataStorageBootstrapAccess saved)) throw unsupported();
            savedAccess = saved; cache = saved.mmmm$bootstrapCache(); dataFolder = saved.mmmm$bootstrapDataFolder();
            type = Objects.requireNonNull(CommandStorageContainerBootstrapAccess.mmmm$bootstrapType(NAMESPACE));
            if (type.getClass() != SavedDataType.class || type.id() == null || type.constructor() == null || type.codec() == null || type.dataFixType() == null
                    || !"mmmm:command_storage".equals(type.id().toString()) || cache == null || dataFolder == null) throw unsupported();
            dataFile = Objects.requireNonNull(saved.mmmm$bootstrapDataFile(type.id()));
            checkCurrent();
        }
        private void checkCurrent() {
            if (!server.isSameThread() || level.getServer() != server || server.getLevel(level.dimension()) != level
                    || level.getScoreboard() != scoreboard || server.getCommandStorage() != storage
                    || storageAccess.mmmm$bootstrapNamespaces() != namespaces || storageAccess.mmmm$bootstrapSavedDataStorage() != savedData
                    || savedAccess.mmmm$bootstrapCache() != cache || savedAccess.mmmm$bootstrapDataFolder() != dataFolder
                    || !savedAccess.mmmm$bootstrapDataFile(type.id()).equals(dataFile)) throw changed();
        }
    }

    private static void requireScope(ObjectNode context, List<NativeCalibrationBootstrap.Program> programs,
                                     NativeCalibrationStateReader.Checkpoint checkpoint) {
        var scope = context.path("scope").path("externalTargetIds");
        if (!scope.isArray() || scope.size() > MAX_MEMBERS || programs.size() != CASE_COUNT) throw unsupported();
        Set<String> ids = new HashSet<>();
        for (var value : scope) {
            checkpoint.check(); if (!value.isTextual() || !ids.add(value.textValue())) throw unsupported();
        }
        Set<String> cases = new HashSet<>(), objectives = new HashSet<>(), storages = new HashSet<>();
        for (var program : programs) {
            checkpoint.check(); String caseId = program.caseId();
            if (caseId == null || !caseId.matches("[a-z][a-z0-9_]{0,127}") || !cases.add(caseId)
                    || program.functionId() == null || !program.functionId().matches("mmmm_calibration:[a-z0-9_./-]{1,256}")
                    || !("mcal" + ContractJson.sha256(caseId.getBytes(StandardCharsets.UTF_8)).substring(0, 11)).equals(program.objective())
                    || !("mmmm:calibration/" + caseId).equals(program.storage())
                    || !objectives.add(program.objective()) || !storages.add(program.storage())
                    || !ids.contains(objectiveId(program)) || !ids.contains(storageId(program))) throw unsupported();
        }
        checkpoint.check();
    }

    private static String objectiveId(NativeCalibrationBootstrap.Program program) { return "calibration-objective-" + program.objective(); }
    private static String storageId(NativeCalibrationBootstrap.Program program) {
        return "calibration-storage-" + ContractJson.sha256(program.storage().getBytes(StandardCharsets.UTF_8));
    }
    private static ContractException unsupported() { return new ContractException("CALIBRATION_BOOTSTRAP_STATE_UNSUPPORTED", "Only actual fresh owned calibration objectives, namespace and backing absence are supported"); }
    private static ContractException changed() { return new ContractException("CALIBRATION_BOOTSTRAP_STATE_CHANGED", "The original native bootstrap state or its ownership changed"); }
    private static ContractException limit() { return new ContractException("CALIBRATION_BOOTSTRAP_STATE_LIMIT", "The native bootstrap state exceeds its finite observation limit"); }
}
