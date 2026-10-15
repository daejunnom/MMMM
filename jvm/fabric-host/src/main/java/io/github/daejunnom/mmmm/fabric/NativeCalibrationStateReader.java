package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.nbt.ByteTag;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.FloatTag;
import net.minecraft.nbt.IntTag;
import net.minecraft.nbt.Tag;
import net.minecraft.resources.Identifier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.storage.CommandStorage;
import net.minecraft.world.scores.Objective;
import net.minecraft.world.scores.ScoreHolder;
import net.minecraft.world.scores.Scoreboard;

/**
 * 봉인된 calibration 주소의 읽기 전용 원자료다. 명령 실행, namespace 로딩,
 * score/objective 생성, seeded/success 판정, 승인과 target profile 발급은 없다.
 */
final class NativeCalibrationStateReader {
    private static final int MAX_ADDRESSES_BYTES = 16 * 1024;
    private static final int MAX_STORAGE_KEYS = 4096;
    private static final int MAX_INPUTS = 128;
    private static final Set<String> ADDRESS_FIELDS = Set.of("caseId", "function", "objective", "storage",
            "ownedStorageSubtrees", "okScore", "staleScore", "staleStorage", "result", "scratch", "inputs");

    private NativeCalibrationStateReader() { }

    enum Presence { PRESENT, ABSENT, UNKNOWN }
    enum Kind { SCORE, INT_TAG, FLOAT_TAG, BYTE_TAG, ABSENT, UNKNOWN }
    enum Unknown { STORAGE_NOT_CACHED, STORAGE_NOT_ADMITTED, PARENT_NOT_COMPOUND, UNSUPPORTED_TAG }

    /** 원값만 보존한다. float는 수치 변환/NaN canonicalization 없이 원 32bit를 보존한다. */
    static final class ScalarFact {
        private final Kind kind;
        private final Integer int32;
        private final Integer rawFloatBits;
        private final Unknown unknown;
        private ScalarFact(Kind kind, Integer int32, Integer rawFloatBits, Unknown unknown) {
            this.kind = kind; this.int32 = int32; this.rawFloatBits = rawFloatBits; this.unknown = unknown;
        }
        Kind kind() { return kind; }
        Integer int32() { return int32; }
        Integer rawFloatBits() { return rawFloatBits; }
        Unknown unknown() { return unknown; }
    }

    /** Test port의 합성 자료도 이 타입을 얻지만 production Snapshot으로 바꿀 수 없다. */
    static final class RawSnapshot {
        private final Presence objectivePresence;
        private final Presence storagePresence;
        private final Presence scratchPresence;
        private final ScalarFact okScore, staleScore, staleStorage, result, staleMarker;
        private final List<ScalarFact> inputs;
        private RawSnapshot(Presence objectivePresence, Presence storagePresence, Presence scratchPresence,
                            ScalarFact okScore, ScalarFact staleScore, ScalarFact staleStorage, ScalarFact result,
                            ScalarFact staleMarker, List<ScalarFact> inputs) {
            this.objectivePresence = objectivePresence; this.storagePresence = storagePresence; this.scratchPresence = scratchPresence;
            this.okScore = okScore; this.staleScore = staleScore; this.staleStorage = staleStorage; this.result = result;
            this.staleMarker = staleMarker; this.inputs = List.copyOf(inputs);
        }
        Presence objectivePresence() { return objectivePresence; }
        Presence storagePresence() { return storagePresence; }
        Presence scratchPresence() { return scratchPresence; }
        ScalarFact okScore() { return okScore; }
        ScalarFact staleScore() { return staleScore; }
        ScalarFact staleStorage() { return staleStorage; }
        ScalarFact result() { return result; }
        ScalarFact staleMarker() { return staleMarker; }
        List<ScalarFact> inputs() { return inputs; }
    }

    /** 실제 native adapter만 발급한다. 원 Control/callback/Session은 보관하지 않는다. */
    static final class Snapshot {
        private final RawSnapshot facts;
        private final long observedFromTick, observedToTick;
        private Snapshot(RawSnapshot facts, long from, long to) {
            this.facts = facts; observedFromTick = from; observedToTick = to;
        }
        RawSnapshot facts() { return facts; }
        long observedFromTick() { return observedFromTick; }
        long observedToTick() { return observedToTick; }
    }

    @FunctionalInterface interface Checkpoint { void check(); }
    record ScoreRead(boolean objectivePresent, Integer value) { }
    record StorageRead(CompoundTag cachedRoot, Unknown unknown) {
        StorageRead {
            if ((cachedRoot == null) == (unknown == null)) throw new IllegalArgumentException("Exactly one storage observation is required");
        }
    }
    /** 순수 scanner test port이며 actual Snapshot/owner/승인 발급 경계가 아니다. */
    interface ReadPort {
        boolean objectivePresent(String objective);
        ScoreRead score(String objective, String holder);
        StorageRead storage(String storage, Checkpoint original);
        void checkCurrent();
    }

    static Snapshot observe(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode installedContext,
                            NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
        Objects.requireNonNull(server); Objects.requireNonNull(level); Objects.requireNonNull(owner);
        Objects.requireNonNull(program); Objects.requireNonNull(control);
        Objects.requireNonNull(installedContext);
        Checkpoint base = () -> {
            control.checkpoint(); owner.checkOpen();
            if (level.getServer() != server || !server.isSameThread()) throw failure("CALIBRATION_STATE_THREAD_REQUIRED");
            // Native 26.3 getLevel is the current levels Map.get only; it does
            // not discover/load a level or accept a detached same-dimension one.
            if (server.getLevel(level.dimension()) != level) throw failure("CALIBRATION_STATE_CHANGED");
            control.checkpoint();
        };
        // The first owner lookup and comparison also belong to the checked
        // boundary. Its failure cannot hide a subsequent original-Control stop.
        return withContext(() -> owner.context(text(installedContext, "contextId")), installedContext, base, context -> {
            Checkpoint checkpoint = () -> {
                base.check();
                if (!"server".equals(owner.side()) || !"game".equals(context.path("environment").path("kind").asText())
                        || !"server".equals(context.path("environment").path("side").asText())
                        || !owner.context(text(context, "contextId")).equals(context)
                        || !level.dimension().identifier().toString().equals(text(context, "dimension"))) {
                    throw failure("CALIBRATION_STATE_CONTEXT_CHANGED");
                }
                base.check();
            };
            checkpoint.check();
            return checked(() -> {
                long from = Integer.toUnsignedLong(server.getTickCount());
                RawSnapshot raw = scan(new ActualPort(server, level), program.caseId(), program.functionId(), program.readbackAddresses(), checkpoint);
                long to = Integer.toUnsignedLong(server.getTickCount());
                return new Snapshot(raw, from, to);
            }, checkpoint);
        });
    }

    /** Comparison test port; only observe() supplies the actual owner lookup. */
    static <T> T withContext(Supplier<ObjectNode> installed, ObjectNode supplied, Checkpoint original, Function<ObjectNode, T> read) {
        original.check();
        return checked(() -> {
            ObjectNode context = Objects.requireNonNull(installed.get());
            if (!context.equals(supplied)) throw failure("CALIBRATION_STATE_CONTEXT_CHANGED");
            original.check(); return read.apply(context);
        }, original);
    }

    static RawSnapshot scan(ReadPort port, String caseId, String functionId, ObjectNode input, Checkpoint original) {
        Objects.requireNonNull(port); Objects.requireNonNull(original);
        Checkpoint checkpoint = () -> { original.check(); port.checkCurrent(); };
        checkpoint.check();
        return checked(() -> {
            Addresses addresses = addresses(caseId, functionId, input);
            checkpoint.check(); boolean objective = port.objectivePresent(addresses.objective); checkpoint.check();
            ScalarFact ok = score(port, addresses.ok, objective, checkpoint);
            ScalarFact staleScore = score(port, addresses.staleScore, objective, checkpoint);
            checkpoint.check(); StorageRead storage = port.storage(addresses.storage, checkpoint); checkpoint.check();
            ScalarFact staleStorage = storage(storage, addresses.staleStorage);
            ScalarFact result = addresses.result.score ? score(port, addresses.result, objective, checkpoint) : storage(storage, addresses.result);
            ScalarFact staleMarker = child(storage, "invocation", "stale");
            var inputs = new ArrayList<ScalarFact>(addresses.inputs.size());
            for (Address address : addresses.inputs) {
                checkpoint.check(); inputs.add(address.score ? score(port, address, objective, checkpoint) : storage(storage, address));
            }
            Presence scratch = storage.cachedRoot == null ? Presence.UNKNOWN
                    : storage.cachedRoot.get("invocation") == null ? Presence.ABSENT : Presence.PRESENT;
            checkpoint.check();
            return new RawSnapshot(objective ? Presence.PRESENT : Presence.ABSENT,
                    storage.cachedRoot == null ? Presence.UNKNOWN : Presence.PRESENT, scratch, ok, staleScore, staleStorage, result, staleMarker, inputs);
        }, checkpoint);
    }

    private static ScalarFact score(ReadPort port, Address address, boolean objective, Checkpoint checkpoint) {
        checkpoint.check(); ScoreRead read = Objects.requireNonNull(port.score(address.objective, address.holder)); checkpoint.check();
        if (read.objectivePresent != objective || !objective && read.value != null) throw failure("CALIBRATION_STATE_CHANGED");
        return read.value == null ? absent() : new ScalarFact(Kind.SCORE, read.value, null, null);
    }
    private static ScalarFact storage(StorageRead storage, Address address) {
        return child(storage, address.parent, address.key);
    }
    private static ScalarFact child(StorageRead storage, String parent, String key) {
        if (storage.cachedRoot == null) return unknown(storage.unknown);
        Tag actual = storage.cachedRoot.get(parent);
        if (actual == null) return absent();
        if (!(actual instanceof CompoundTag compound) || actual.getClass() != CompoundTag.class) return unknown(Unknown.PARENT_NOT_COMPOUND);
        return scalar(compound.get(key));
    }
    private static ScalarFact scalar(Tag actual) {
        if (actual == null) return absent();
        // Exact 26.3 field getters: no numeric coercion or NBT serialization.
        if (actual.getClass() == IntTag.class) return new ScalarFact(Kind.INT_TAG, ((IntTag) actual).intValue(), null, null);
        if (actual.getClass() == FloatTag.class) return new ScalarFact(Kind.FLOAT_TAG, null,
                Float.floatToRawIntBits(((FloatTag) actual).floatValue()), null);
        if (actual.getClass() == ByteTag.class) return new ScalarFact(Kind.BYTE_TAG, (int) ((ByteTag) actual).byteValue(), null, null);
        return unknown(Unknown.UNSUPPORTED_TAG);
    }

    private record Address(boolean score, String objective, String holder, String parent, String key) { }
    private record Addresses(String objective, String storage, Address ok, Address staleScore, Address staleStorage,
                             Address result, List<Address> inputs) { }
    private static Addresses addresses(String caseId, String functionId, ObjectNode input) {
        if (caseId == null || !caseId.matches("[a-z][a-z0-9_]{0,127}") || functionId == null
                || !functionId.matches("mmmm_calibration:[a-z0-9_./-]{1,256}")) throw invalid();
        if (ContractJson.bytes(input).length > MAX_ADDRESSES_BYTES) throw failure("CALIBRATION_STATE_LIMIT");
        ObjectNode value = input.deepCopy(); exact(value, ADDRESS_FIELDS);
        String objective = "mcal" + ContractJson.sha256(caseId.getBytes(StandardCharsets.UTF_8)).substring(0, 11);
        String storage = "mmmm:calibration/" + caseId;
        if (!caseId.equals(text(value, "caseId")) || !functionId.equals(text(value, "function"))
                || !objective.equals(text(value, "objective")) || !storage.equals(text(value, "storage"))
                || !value.path("ownedStorageSubtrees").equals(ContractJson.newObject().putArray("subtrees").add("inputs").add("invocation"))) throw invalid();
        Address ok = scoreAddress(value.path("okScore"), objective, "#ok");
        Address staleScore = scoreAddress(value.path("staleScore"), objective, "#result");
        Address staleStorage = storageAddress(value.path("staleStorage"), storage, "invocation", "result");
        ObjectNode scratch = ContractJson.object(value.path("scratch")); exact(scratch, Set.of("kind", "storage", "path"));
        if (!"storage".equals(text(scratch, "kind")) || !storage.equals(text(scratch, "storage")) || !"invocation".equals(text(scratch, "path"))) throw invalid();
        JsonNode result = value.path("result");
        Address output = "score".equals(result.path("kind").asText()) ? scoreAddress(result, objective, "#result")
                : storageAddress(result, storage, "invocation", "result");
        JsonNode inputs = value.path("inputs");
        if (!inputs.isArray() || inputs.size() > MAX_INPUTS) throw invalid();
        var addresses = new ArrayList<Address>(inputs.size()); var indices = new HashSet<Integer>();
        for (JsonNode entry : inputs) {
            boolean score = "score".equals(entry.path("kind").asText());
            String location = text(ContractJson.object(entry), score ? "holder" : "path");
            String prefix = score ? "#input" : "inputs.n";
            if (!location.startsWith(prefix) || !location.substring(prefix.length()).matches("0|[1-9][0-9]{0,2}")) throw invalid();
            int index = Integer.parseInt(location.substring(prefix.length()));
            if (index >= MAX_INPUTS || !indices.add(index)) throw invalid();
            addresses.add(score ? scoreAddress(entry, objective, location) : storageAddress(entry, storage, "inputs", "n" + index));
        }
        return new Addresses(objective, storage, ok, staleScore, staleStorage, output, List.copyOf(addresses));
    }
    private static Address scoreAddress(JsonNode input, String objective, String holder) {
        ObjectNode value = ContractJson.object(input); exact(value, Set.of("kind", "holder", "objective"));
        if (!"score".equals(text(value, "kind")) || !holder.equals(text(value, "holder")) || !objective.equals(text(value, "objective"))) throw invalid();
        return new Address(true, objective, holder, null, null);
    }
    private static Address storageAddress(JsonNode input, String storage, String parent, String key) {
        ObjectNode value = ContractJson.object(input); exact(value, Set.of("kind", "storage", "path"));
        if (!"storage".equals(text(value, "kind")) || !storage.equals(text(value, "storage")) || !(parent + "." + key).equals(text(value, "path"))) throw invalid();
        return new Address(false, null, null, parent, key);
    }

    private static final class ActualPort implements ReadPort {
        private final MinecraftServer server;
        private final ServerLevel level;
        private final Scoreboard scoreboard;
        private final CommandStorage storage;
        private String objectiveName;
        private Objective objective;
        private ActualPort(MinecraftServer server, ServerLevel level) {
            this.server = server; this.level = level; scoreboard = level.getScoreboard(); storage = server.getCommandStorage();
        }
        @Override public boolean objectivePresent(String name) {
            objectiveName = name; objective = scoreboard.getObjective(name);
            if (objective != null && !name.equals(objective.getName())) throw failure("CALIBRATION_STATE_CHANGED");
            return objective != null;
        }
        @Override public ScoreRead score(String name, String holder) {
            if (!name.equals(objectiveName)) throw invalid(); checkCurrent();
            var actual = objective == null ? null : scoreboard.getPlayerScoreInfo(ScoreHolder.forNameOnly(holder), objective);
            return new ScoreRead(objective != null, actual == null ? null : actual.value());
        }
        @Override public StorageRead storage(String expected, Checkpoint checkpoint) {
            if (storage == null || storage.getClass() != CommandStorage.class) return new StorageRead(null, Unknown.STORAGE_NOT_ADMITTED);
            Identifier observed;
            // Verified native keys() streams cached containers only. Complete
            // bounded membership precedes get(), so no absent namespace loads.
            try (var keys = storage.keys()) {
                observed = cachedKey(keys.iterator(), expected, checkpoint);
            }
            checkpoint.check();
            if (observed == null) return new StorageRead(null, Unknown.STORAGE_NOT_CACHED);
            CompoundTag root = storage.get(observed);
            if (root == null || root.getClass() != CompoundTag.class) return new StorageRead(null, Unknown.STORAGE_NOT_ADMITTED);
            return new StorageRead(root, null);
        }
        @Override public void checkCurrent() {
            if (level.getServer() != server || !server.isSameThread() || level.getScoreboard() != scoreboard
                    || server.getLevel(level.dimension()) != level || server.getCommandStorage() != storage
                    || objectiveName != null && scoreboard.getObjective(objectiveName) != objective) {
                throw failure("CALIBRATION_STATE_CHANGED");
            }
        }
    }

    /** Complete bounded cache membership; an early match cannot skip the cap. */
    static <K> K cachedKey(Iterator<K> keys, String expected, Checkpoint checkpoint) {
        K observed = null; int count = 0;
        while (keys.hasNext()) {
            checkpoint.check(); if (++count > MAX_STORAGE_KEYS) throw failure("CALIBRATION_STATE_LIMIT");
            K key = keys.next();
            if (key == null) throw failure("CALIBRATION_STATE_CHANGED");
            if (expected.equals(key.toString())) { if (observed != null) throw failure("CALIBRATION_STATE_CHANGED"); observed = key; }
        }
        checkpoint.check(); return observed;
    }

    private static <T> T checked(Supplier<T> read, Checkpoint checkpoint) {
        Throwable primary = null;
        try { return read.get(); }
        catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            try { checkpoint.check(); }
            catch (RuntimeException | Error after) { if (primary == null) throw after; if (after != primary) primary.addSuppressed(after); }
        }
    }
    private static ScalarFact absent() { return new ScalarFact(Kind.ABSENT, null, null, null); }
    private static ScalarFact unknown(Unknown reason) { return new ScalarFact(Kind.UNKNOWN, null, null, reason); }
    private static void exact(ObjectNode value, Set<String> fields) {
        if (value.size() != fields.size()) throw invalid();
        value.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); });
    }
    private static String text(ObjectNode value, String field) { if (!value.path(field).isTextual()) throw invalid(); return value.path(field).textValue(); }
    private static ContractException invalid() { return failure("CALIBRATION_STATE_ADDRESS_UNSUPPORTED"); }
    private static ContractException failure(String code) { return new ContractException(code, "The original fixed calibration state is unavailable or changed"); }
}
