package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import net.minecraft.nbt.Tag;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.storage.CommandStorage;
import net.minecraft.world.scores.Scoreboard;

/** Whole actual objective and the exact two owned storage subtrees; no execution or approval is issued. */
final class NativeCalibrationTargetImages {
    static final String FORMAT = "mmmm.native.calibration-target/1";
    static final int MAX_TARGET_BYTES = 256 * 1024;
    static final int MAX_PAIR_BYTES = 512 * 1024;
    private static final int MAX_BINDING_BYTES = 4096;
    private static final int MAX_SCOPE_TARGETS = 4096;
    private NativeCalibrationTargetImages() { }
    @FunctionalInterface interface Checkpoint { void check(); }

    /** Strict selection/comparison data, never a grant, loaded-source receipt or sealed-program proof. */
    static final class ReadonlySelection {
        private final String objectiveTargetId, storageTargetId, objective, storage;
        private ReadonlySelection(String objectiveTargetId, String storageTargetId, String objective, String storage) {
            this.objectiveTargetId = objectiveTargetId; this.storageTargetId = storageTargetId;
            this.objective = objective; this.storage = storage;
        }
        private List<String> targetIds() { return List.of(objectiveTargetId, storageTargetId); }
        private ObjectNode objectiveSelector() { return ContractJson.newObject().put("targetId", objectiveTargetId).put("kind", "objective").put("objective", objective); }
        private ObjectNode storageSelector() {
            ObjectNode value = ContractJson.newObject().put("targetId", storageTargetId).put("kind", "owned_storage").put("storage", storage);
            value.putArray("ownedSubtrees").add("inputs").add("invocation"); return value;
        }
    }

    /** Only actual observe()/observeSelected() can construct this native pair. No callbacks/native mutable objects are retained. */
    static final class ImagePair {
        private final RawPair raw;
        private final long fromTick, toTick;
        private ImagePair(RawPair raw, long fromTick, long toTick) { this.raw = raw; this.fromTick = fromTick; this.toTick = toTick; }
        String objectiveTargetId() { return raw.objectiveTargetId; }
        String storageTargetId() { return raw.storageTargetId; }
        byte[] objectiveBytes() { return raw.objectiveBytes(); }
        byte[] storageBytes() { return raw.storageBytes(); }
        String objectiveSha256() { return raw.objectiveSha256; }
        String storageSha256() { return raw.storageSha256; }
        boolean objectiveFullTargetKnown() { return raw.objectiveKnown; }
        boolean storageFullTargetKnown() { return raw.storageKnown; }
        long observedFromTick() { return fromTick; }
        long observedToTick() { return toTick; }
    }

    /** Synthetic port observations remain data, and cannot be converted to a production ImagePair. */
    static final class RawPair {
        private final String objectiveTargetId, storageTargetId, objectiveSha256, storageSha256;
        private final byte[] objectiveBytes, storageBytes;
        private final boolean objectiveKnown, storageKnown;
        private RawPair(ReadonlySelection selected, ObjectNode objective, ObjectNode storage) {
            objectiveTargetId = selected.objectiveTargetId; storageTargetId = selected.storageTargetId;
            objectiveBytes = encoded(objective); storageBytes = encoded(storage);
            if ((long) objectiveBytes.length + storageBytes.length > MAX_PAIR_BYTES) throw limit();
            objectiveSha256 = ContractJson.sha256(objectiveBytes); storageSha256 = ContractJson.sha256(storageBytes);
            objectiveKnown = fullKnown(objective); storageKnown = fullKnown(storage);
        }
        byte[] objectiveBytes() { return objectiveBytes.clone(); }
        byte[] storageBytes() { return storageBytes.clone(); }
        String objectiveSha256() { return objectiveSha256; }
        String storageSha256() { return storageSha256; }
        boolean objectiveFullTargetKnown() { return objectiveKnown; }
        boolean storageFullTargetKnown() { return storageKnown; }
    }

    interface ReadPort {
        ObjectNode objective(String objective, NativeCalibrationStateReader.Checkpoint checkpoint);
        NativeCommandStorageCache.Facts storage(String storage, NativeCalibrationStateReader.Checkpoint checkpoint);
        void checkCurrent();
        default void checkComplete(NativeCalibrationStateReader.Checkpoint checkpoint) { checkpoint.check(); }
    }

    static ImagePair observe(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode context,
                             NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
        Objects.requireNonNull(program); Objects.requireNonNull(control); control.checkpoint();
        var bindings = program.targetBindings();
        if (bindings.size() != 2) throw invalid();
        var objective = bindings.get(0); var storage = bindings.get(1);
        if (!"objective".equals(objective.kind()) || !"owned_storage".equals(storage.kind())
                || !storage.ownedSubtrees().equals(List.of("inputs", "invocation"))) throw invalid();
        ReadonlySelection selected = selection(program.caseId(), program.functionId(), objective.targetId(), storage.targetId(), objective.objective(), storage.storage());
        if (!program.resourcesRead().equals(selected.targetIds()) || !program.resourcesWritten().equals(selected.targetIds())) throw invalid();
        control.checkpoint(); return observeSelected(server, level, owner, context, selected, control::checkpoint);
    }

    static ImagePair observeSelected(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode context,
                                     ReadonlySelection selected, Checkpoint original) {
        Objects.requireNonNull(selected); Objects.requireNonNull(original);
        return NativeCalibrationStateReader.currentContext(server, level, owner, context, original::check, (current, checkpoint) -> {
            requireScope(current, selected, checkpoint);
            long from = Integer.toUnsignedLong(server.getTickCount());
            RawPair raw = scan(new ActualPort(server, level), current, selected, checkpoint);
            checkpoint.check();
            return new ImagePair(raw, from, Integer.toUnsignedLong(server.getTickCount()));
        });
    }

    static ReadonlySelection select(String caseId, String functionId, JsonNode bindings) {
        if (bindings == null || !bindings.isArray() || bindings.size() != 2 || ContractJson.bytes(bindings).length > MAX_BINDING_BYTES) throw invalid();
        ObjectNode objective = ContractJson.object(bindings.get(0)), storage = ContractJson.object(bindings.get(1));
        exact(objective, Set.of("targetId", "kind", "objective")); exact(storage, Set.of("targetId", "kind", "storage", "ownedSubtrees"));
        if (!"objective".equals(text(objective, "kind")) || !"owned_storage".equals(text(storage, "kind"))
                || !storage.path("ownedSubtrees").equals(ContractJson.newObject().putArray("subtrees").add("inputs").add("invocation"))) throw invalid();
        return selection(caseId, functionId, text(objective, "targetId"), text(storage, "targetId"), text(objective, "objective"), text(storage, "storage"));
    }

    private static ReadonlySelection selection(String caseId, String functionId, String objectiveId, String storageId, String objective, String storage) {
        if (caseId == null || !caseId.matches("[a-z][a-z0-9_]{0,127}") || functionId == null
                || !functionId.matches("mmmm_calibration:[a-z0-9_./-]{1,256}")) throw invalid();
        String exactObjective = "mcal" + ContractJson.sha256(caseId.getBytes(StandardCharsets.UTF_8)).substring(0, 11);
        String exactStorage = "mmmm:calibration/" + caseId;
        if (!exactObjective.equals(objective) || !exactStorage.equals(storage)
                || !("calibration-objective-" + exactObjective).equals(objectiveId)
                || !("calibration-storage-" + ContractJson.sha256(exactStorage.getBytes(StandardCharsets.UTF_8))).equals(storageId)) throw invalid();
        return new ReadonlySelection(objectiveId, storageId, objective, storage);
    }

    static RawPair scan(ReadPort port, ObjectNode context, ReadonlySelection selected, NativeCalibrationStateReader.Checkpoint original) {
        Objects.requireNonNull(port); Objects.requireNonNull(selected); Objects.requireNonNull(original);
        NativeCalibrationStateReader.Checkpoint checkpoint = () -> { original.check(); port.checkCurrent(); };
        checkpoint.check(); requireScope(context, selected, original);
        return NativeCalibrationStateReader.checked(() -> {
            checkpoint.check(); ObjectNode objectiveFacts = port.objective(selected.objective, checkpoint); checkpoint.check();
            ObjectNode objective = objective(selected, objectiveFacts);
            checkpoint.check(); var cached = port.storage(selected.storage, checkpoint); checkpoint.check();
            ObjectNode storage = storage(selected, cached, checkpoint);
            checkpoint.check(); requireScope(context, selected, original);
            RawPair images = new RawPair(selected, objective, storage);
            port.checkComplete(checkpoint); checkpoint.check(); return images;
        }, checkpoint);
    }

    private static ObjectNode objective(ReadonlySelection selected, ObjectNode facts) {
        if (!"mmmm.native.target/1".equals(facts.path("format").asText())
                || !selected.objective.equals(facts.path("selector").path("objective").asText())
                || !"objective".equals(facts.path("selector").path("kind").asText())) throw invalid();
        ObjectNode image = base(selected.objectiveSelector());
        if ("known".equals(facts.path("status").asText())) {
            if (!"full_target".equals(facts.path("coverage").asText())
                    || !"native_objective_and_all_scores".equals(facts.path("captureScope").asText())
                    || !Set.of("present", "absent").contains(facts.path("presence").asText())) throw invalid();
        } else if (!"unknown".equals(facts.path("status").asText())) throw invalid();
        for (String field : List.of("status", "presence", "membershipScope", "captureScope", "coverage", "reason", "payload")) {
            if (!facts.has(field)) throw invalid(); image.set(field, facts.get(field).deepCopy());
        }
        return image;
    }

    private static ObjectNode storage(ReadonlySelection selected, NativeCommandStorageCache.Facts storage,
                                      NativeCalibrationStateReader.Checkpoint checkpoint) {
        ObjectNode image = base(selected.storageSelector());
        if (storage.state() == NativeCommandStorageCache.State.NAMESPACE_UNKNOWN || storage.state() == NativeCommandStorageCache.State.NOT_ADMITTED) {
            return image.put("captureScope", "native_owned_storage_subtrees").put("reason",
                    storage.state() == NativeCommandStorageCache.State.NAMESPACE_UNKNOWN ? "native_storage_namespace_not_observed" : "native_storage_source_not_admitted");
        }
        ObjectNode payload = ContractJson.newObject().put("storagePresent", storage.state() == NativeCommandStorageCache.State.PRESENT); boolean present = false;
        for (String subtree : List.of("inputs", "invocation")) {
            checkpoint.check(); Tag actual = storage.cachedRoot() == null ? null : storage.cachedRoot().get(subtree);
            ObjectNode value = ContractJson.newObject().put("presence", actual == null ? "absent" : "present");
            if (actual == null) value.putNull("nativeValueNbt");
            else { value.set("nativeValueNbt", NativeTargets.encodeNativeTag(actual, checkpoint::check)); present = true; }
            payload.set(subtree, value);
            if (storage.cachedRoot() != null && storage.cachedRoot().get(subtree) != actual) throw failure("CALIBRATION_STATE_CHANGED");
            checkpoint.check();
        }
        image.put("status", "known").put("presence", present ? "present" : "absent")
                .put("membershipScope", "current_cached_command_storage").put("captureScope", "native_owned_storage_subtrees")
                .put("coverage", "full_target").putNull("reason"); image.set("payload", payload); return image;
    }

    private static void requireScope(ObjectNode context, ReadonlySelection selected, NativeCalibrationStateReader.Checkpoint checkpoint) {
        JsonNode ids = context.path("scope").path("externalTargetIds");
        if (!ids.isArray() || ids.size() > MAX_SCOPE_TARGETS) throw failure("SCOPE_DENIED");
        boolean objective = false, storage = false;
        for (JsonNode id : ids) {
            checkpoint.check(); if (!id.isTextual()) throw failure("SCOPE_DENIED");
            objective |= selected.objectiveTargetId.equals(id.textValue()); storage |= selected.storageTargetId.equals(id.textValue());
        }
        if (!objective || !storage) throw failure("SCOPE_DENIED");
    }

    private static final class ActualPort implements ReadPort {
        private final MinecraftServer server;
        private final ServerLevel level;
        private final Scoreboard scoreboard;
        private final CommandStorage storage;
        private NativeCommandStorageCache.Read cached;
        private ActualPort(MinecraftServer server, ServerLevel level) {
            this.server = server; this.level = level; scoreboard = level.getScoreboard(); storage = server.getCommandStorage();
        }
        @Override public ObjectNode objective(String name, NativeCalibrationStateReader.Checkpoint checkpoint) { return NativeTargets.readObjectiveImage(level, name, checkpoint::check); }
        @Override public NativeCommandStorageCache.Facts storage(String name, NativeCalibrationStateReader.Checkpoint checkpoint) {
            cached = NativeCalibrationStateReader.cachedStorage(server, name, checkpoint); return cached.facts();
        }
        @Override public void checkComplete(NativeCalibrationStateReader.Checkpoint checkpoint) {
            if (cached == null) throw failure("CALIBRATION_STATE_CHANGED"); cached.checkComplete(checkpoint);
        }
        @Override public void checkCurrent() {
            if (!server.isSameThread() || level.getServer() != server || server.getLevel(level.dimension()) != level
                    || level.getScoreboard() != scoreboard || server.getCommandStorage() != storage) throw failure("CALIBRATION_STATE_CHANGED");
            if (cached != null) cached.checkCurrent();
        }
    }

    private static ObjectNode base(ObjectNode selector) {
        ObjectNode image = ContractJson.newObject().put("format", FORMAT); image.set("selector", selector);
        return image.put("status", "unknown").put("presence", "unknown").put("membershipScope", "unknown")
                .put("captureScope", "unknown").put("coverage", "best_effort").putNull("reason").putNull("payload");
    }
    private static byte[] encoded(ObjectNode image) { byte[] bytes = ContractJson.canonical(image); if (bytes.length > MAX_TARGET_BYTES) throw limit(); return bytes; }
    private static boolean fullKnown(ObjectNode image) { return "known".equals(image.path("status").asText()) && "full_target".equals(image.path("coverage").asText()); }
    private static void exact(ObjectNode value, Set<String> fields) {
        if (value.size() != fields.size()) throw invalid(); value.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); });
    }
    private static String text(ObjectNode value, String field) { if (!value.path(field).isTextual()) throw invalid(); return value.path(field).textValue(); }
    private static ContractException invalid() { return failure("CALIBRATION_TARGET_BINDING_UNSUPPORTED"); }
    private static ContractException limit() { return failure("CALIBRATION_TARGET_IMAGE_LIMIT"); }
    private static ContractException failure(String code) { return new ContractException(code, "The exact current calibration target image is unavailable or changed"); }
}
