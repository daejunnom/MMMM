package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import net.minecraft.nbt.ByteTag;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.FloatTag;
import net.minecraft.nbt.IntTag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 합성 read port 검사이며 native server/ADMIN/실제 calibration의 증거가 아니다. */
final class NativeCalibrationStateReaderTest {
    private static final String CASE = "int_add";
    private static final String FUNCTION = "mmmm_calibration:int_add";
    private static final String OBJECTIVE = "mcal" + ContractJson.sha256(CASE.getBytes(StandardCharsets.UTF_8)).substring(0, 11);
    private static final String STORAGE = "mmmm:calibration/" + CASE;

    @Test void fixedScoreReadsKeepActualValuesAndUncachedStorageIsUnknownWithoutInferredSeededSuccess() {
        var port = new Port(); ObjectNode address = addresses(); address.set("result", score("#result"));
        var raw = NativeCalibrationStateReader.scan(port, CASE, FUNCTION, address, () -> { });
        assertEquals(NativeCalibrationStateReader.Presence.PRESENT, raw.objectivePresence());
        assertEquals(NativeCalibrationStateReader.Presence.UNKNOWN, raw.storagePresence());
        assertEquals(NativeCalibrationStateReader.Presence.UNKNOWN, raw.scratchPresence());
        assertEquals(NativeCalibrationStateReader.Kind.SCORE, raw.okScore().kind()); assertEquals(-7, raw.okScore().int32());
        assertEquals(7331, raw.staleScore().int32()); assertEquals(7331, raw.result().int32());
        assertEquals(Integer.MIN_VALUE, raw.inputs().get(0).int32());
        assertEquals(NativeCalibrationStateReader.Unknown.STORAGE_NOT_CACHED, raw.inputs().get(1).unknown());
        assertEquals(NativeCalibrationStateReader.Kind.UNKNOWN, raw.staleStorage().kind());
        assertNull(raw.staleStorage().int32()); assertNull(raw.staleStorage().rawFloatBits());
        assertThrows(UnsupportedOperationException.class, () -> raw.inputs().clear());
        assertEquals(1, port.storageCalls.get()); assertEquals(4, port.scoreCalls.get());
        port.objective = false;
        var absent = NativeCalibrationStateReader.scan(port, CASE, FUNCTION, address, () -> { });
        assertEquals(NativeCalibrationStateReader.Presence.ABSENT, absent.objectivePresence());
        assertEquals(NativeCalibrationStateReader.Kind.ABSENT, absent.okScore().kind());
        assertEquals(NativeCalibrationStateReader.Kind.UNKNOWN, absent.staleStorage().kind());
        for (String field : List.of("objective", "storage", "ownedStorageSubtrees", "scratch", "okScore", "staleScore", "staleStorage", "result", "inputs")) {
            var changed = addresses(); changed.put(field, "arbitrary"); var denied = new Port();
            assertThrows(ContractException.class, () -> NativeCalibrationStateReader.scan(denied, CASE, FUNCTION, changed, () -> { }), field);
            assertEquals(0, denied.storageCalls.get()); assertEquals(0, denied.scoreCalls.get());
        }
        for (String path : List.of("inputs", "invocation.result[0]", "invocation.*", "other.result", "inputs.n128", "inputs.n01")) {
            var changed = addresses(); changed.withArray("inputs").set(1, storage(path));
            assertThrows(ContractException.class, () -> NativeCalibrationStateReader.scan(new Port(), CASE, FUNCTION, changed, () -> { }), path);
        }
        var duplicate = addresses(); duplicate.withArray("inputs").set(1, storage("inputs.n0"));
        assertThrows(ContractException.class, () -> NativeCalibrationStateReader.scan(new Port(), CASE, FUNCTION, duplicate, () -> { }));
        var drift = new Port() {
            @Override public NativeCalibrationStateReader.ScoreRead score(String name, String holder) {
                scoreCalls.incrementAndGet(); return new NativeCalibrationStateReader.ScoreRead(false, null);
            }
        };
        assertThrows(ContractException.class, () -> NativeCalibrationStateReader.scan(drift, CASE, FUNCTION, addresses(), () -> { }));
        assertEquals(0, drift.storageCalls.get()); assertEquals(1, drift.scoreCalls.get());
        var detached = new Port() {
            @Override public void checkCurrent() { throw new ContractException("CALIBRATION_STATE_CHANGED", "current level unavailable"); }
        };
        assertThrows(ContractException.class, () -> NativeCalibrationStateReader.scan(detached, CASE, FUNCTION, addresses(), () -> { }));
        assertEquals(0, detached.storageCalls.get()); assertEquals(0, detached.scoreCalls.get());
    }

    @Test void cachedFixedNativeTagsKeepRawFloatBitsIntegersMarkersAbsenceAndImmutableFacts() {
        var root = new CompoundTag(); var invocation = new CompoundTag(); var inputs = new CompoundTag();
        // Fixed 26.3 factory and native decoder fold -0: one raw ABI compatibility input.
        @SuppressWarnings("removal")
        FloatTag negativeZero = new FloatTag(-0F);
        invocation.put("result", negativeZero); invocation.put("stale", ByteTag.valueOf((byte) 1));
        inputs.put("n1", IntTag.valueOf(Integer.MAX_VALUE)); root.put("invocation", invocation); root.put("inputs", inputs);
        var port = new Port() {
            @Override public NativeCalibrationStateReader.StorageRead storage(String id, NativeCalibrationStateReader.Checkpoint checkpoint) {
                assertEquals(STORAGE, id); storageCalls.incrementAndGet(); return new NativeCalibrationStateReader.StorageRead(root, null);
            }
        };
        var raw = NativeCalibrationStateReader.scan(port, CASE, FUNCTION, addresses(), () -> { });
        assertEquals(NativeCalibrationStateReader.Presence.PRESENT, raw.storagePresence());
        assertEquals(NativeCalibrationStateReader.Presence.PRESENT, raw.scratchPresence());
        assertEquals(NativeCalibrationStateReader.Kind.FLOAT_TAG, raw.result().kind());
        assertEquals(0x80000000, raw.result().rawFloatBits()); assertNull(raw.result().int32());
        assertEquals(0x80000000, raw.staleStorage().rawFloatBits());
        assertEquals(NativeCalibrationStateReader.Kind.BYTE_TAG, raw.staleMarker().kind()); assertEquals(1, raw.staleMarker().int32());
        assertEquals(NativeCalibrationStateReader.Kind.INT_TAG, raw.inputs().get(1).kind()); assertEquals(Integer.MAX_VALUE, raw.inputs().get(1).int32());
        invocation.put("result", FloatTag.valueOf(Float.intBitsToFloat(0x7fc12345)));
        var nan = NativeCalibrationStateReader.scan(port, CASE, FUNCTION, addresses(), () -> { });
        assertEquals(0x7fc12345, nan.result().rawFloatBits()); assertEquals(0x80000000, raw.result().rawFloatBits());
        invocation.put("result", IntTag.valueOf(-19));
        assertEquals(-19, NativeCalibrationStateReader.scan(port, CASE, FUNCTION, addresses(), () -> { }).result().int32());
        root.put("invocation", new CompoundTag()); root.put("inputs", new CompoundTag());
        var empty = NativeCalibrationStateReader.scan(port, CASE, FUNCTION, addresses(), () -> { });
        assertEquals(NativeCalibrationStateReader.Presence.PRESENT, empty.scratchPresence());
        assertEquals(NativeCalibrationStateReader.Kind.ABSENT, empty.result().kind());
        assertEquals(NativeCalibrationStateReader.Kind.ABSENT, empty.staleMarker().kind());
        assertEquals(NativeCalibrationStateReader.Kind.ABSENT, empty.inputs().get(1).kind());
        var emptyPort = new Port() {
            @Override public NativeCalibrationStateReader.StorageRead storage(String id, NativeCalibrationStateReader.Checkpoint checkpoint) {
                return new NativeCalibrationStateReader.StorageRead(new CompoundTag(), null);
            }
        };
        var absent = NativeCalibrationStateReader.scan(emptyPort, CASE, FUNCTION, addresses(), () -> { });
        assertEquals(NativeCalibrationStateReader.Presence.ABSENT, absent.scratchPresence());
        root.put("invocation", IntTag.valueOf(7));
        var wrongParent = NativeCalibrationStateReader.scan(port, CASE, FUNCTION, addresses(), () -> { });
        assertEquals(NativeCalibrationStateReader.Presence.PRESENT, wrongParent.scratchPresence());
        assertEquals(NativeCalibrationStateReader.Unknown.PARENT_NOT_COMPOUND, wrongParent.result().unknown());
        var unsupported = new CompoundTag(); unsupported.put("result", new CompoundTag()); root.put("invocation", unsupported);
        assertEquals(NativeCalibrationStateReader.Unknown.UNSUPPORTED_TAG,
                NativeCalibrationStateReader.scan(port, CASE, FUNCTION, addresses(), () -> { }).result().unknown());
    }

    @Test void originalReadFailureKeepsSubsequentRevocationAndNeverRetriesOrPublishesPartialFacts() {
        var primary = new ContractException("NATIVE_READ_FAILED", "actual read failed");
        var revoked = new ContractException("SOURCE_REVOKED", "actual source revoked");
        var stop = new AtomicBoolean(); var port = new Port() {
            @Override public NativeCalibrationStateReader.StorageRead storage(String id, NativeCalibrationStateReader.Checkpoint checkpoint) {
                storageCalls.incrementAndGet(); stop.set(true); throw primary;
            }
        };
        RuntimeException actual = assertThrows(RuntimeException.class, () -> NativeCalibrationStateReader.scan(port, CASE, FUNCTION,
                addresses(), () -> { if (stop.get()) throw revoked; }));
        assertSame(primary, actual); assertArrayEquals(new Throwable[]{revoked}, actual.getSuppressed());
        assertEquals(1, port.storageCalls.get()); assertEquals(2, port.scoreCalls.get());
        var before = new Port();
        assertSame(revoked, assertThrows(ContractException.class, () -> NativeCalibrationStateReader.scan(before, CASE, FUNCTION,
                addresses(), () -> { throw revoked; })));
        assertEquals(0, before.storageCalls.get()); assertEquals(0, before.scoreCalls.get());
        var lookupFailure = new ContractException("CONTEXT_READ_FAILED", "original owner lookup failed");
        var afterLookup = new AtomicBoolean(); var nativeReads = new AtomicInteger(); ObjectNode supplied = ContractJson.newObject().put("contextId", "fixture");
        assertSame(lookupFailure, assertThrows(ContractException.class, () -> NativeCalibrationStateReader.withContext(
                () -> { afterLookup.set(true); throw lookupFailure; }, supplied,
                () -> { if (afterLookup.get()) throw revoked; }, context -> nativeReads.incrementAndGet())));
        assertArrayEquals(new Throwable[]{revoked}, lookupFailure.getSuppressed()); assertEquals(0, nativeReads.get());
        afterLookup.set(false);
        ContractException mismatch = assertThrows(ContractException.class, () -> NativeCalibrationStateReader.withContext(
                () -> { afterLookup.set(true); return supplied.deepCopy().put("contextId", "replacement"); }, supplied,
                () -> { if (afterLookup.getAndSet(false)) throw revoked; }, context -> nativeReads.incrementAndGet()));
        assertEquals("CALIBRATION_STATE_CONTEXT_CHANGED", mismatch.code());
        assertArrayEquals(new Throwable[]{revoked}, mismatch.getSuppressed()); assertEquals(0, nativeReads.get());
    }

    @Test void completeCachedMembershipHonorsTheCapAfterAnEarlyMatchAndOriginalCheckpoint() {
        var exact = new ArrayList<String>(); exact.add(STORAGE);
        for (int index = 1; index < 4096; index++) exact.add("fixture:other/" + index);
        assertEquals(STORAGE, NativeCalibrationStateReader.cachedKey(exact.iterator(), STORAGE, () -> { }));
        assertNull(NativeCalibrationStateReader.cachedKey(List.of("fixture:other").iterator(), STORAGE, () -> { }));
        exact.add("fixture:past-the-cap");
        ContractException limit = assertThrows(ContractException.class, () -> NativeCalibrationStateReader.cachedKey(exact.iterator(), STORAGE, () -> { }));
        assertEquals("CALIBRATION_STATE_LIMIT", limit.code());
        assertThrows(ContractException.class, () -> NativeCalibrationStateReader.cachedKey(List.of(STORAGE, STORAGE).iterator(), STORAGE, () -> { }));
        var checks = new AtomicInteger(); var stopped = new ContractException("ORIGINAL_CANCELLED", "original cancelled");
        assertSame(stopped, assertThrows(ContractException.class, () -> NativeCalibrationStateReader.cachedKey(exact.iterator(), STORAGE,
                () -> { if (checks.incrementAndGet() == 4) throw stopped; })));
        assertEquals(4, checks.get());
    }

    private static class Port implements NativeCalibrationStateReader.ReadPort {
        boolean objective = true;
        final AtomicInteger scoreCalls = new AtomicInteger(), storageCalls = new AtomicInteger();
        @Override public boolean objectivePresent(String name) { assertEquals(OBJECTIVE, name); return objective; }
        @Override public NativeCalibrationStateReader.ScoreRead score(String objectiveName, String holder) {
            assertEquals(OBJECTIVE, objectiveName); scoreCalls.incrementAndGet();
            Integer value = !objective ? null : switch (holder) { case "#ok" -> -7; case "#result" -> 7331; case "#input0" -> Integer.MIN_VALUE; default -> throw new AssertionError(holder); };
            return new NativeCalibrationStateReader.ScoreRead(objective, value);
        }
        @Override public NativeCalibrationStateReader.StorageRead storage(String id, NativeCalibrationStateReader.Checkpoint checkpoint) {
            assertEquals(STORAGE, id); storageCalls.incrementAndGet();
            return new NativeCalibrationStateReader.StorageRead(null, NativeCalibrationStateReader.Unknown.STORAGE_NOT_CACHED);
        }
        @Override public void checkCurrent() { }
    }
    private static ObjectNode score(String holder) { return ContractJson.newObject().put("kind", "score").put("holder", holder).put("objective", OBJECTIVE); }
    private static ObjectNode storage(String path) { return ContractJson.newObject().put("kind", "storage").put("storage", STORAGE).put("path", path); }
    private static ObjectNode addresses() {
        ObjectNode value = ContractJson.newObject().put("caseId", CASE).put("function", FUNCTION).put("objective", OBJECTIVE).put("storage", STORAGE);
        value.putArray("ownedStorageSubtrees").add("inputs").add("invocation");
        value.set("okScore", score("#ok")); value.set("staleScore", score("#result")); value.set("staleStorage", storage("invocation.result"));
        value.set("result", storage("invocation.result")); value.set("scratch", storage("invocation"));
        value.putArray("inputs").add(score("#input0")).add(storage("inputs.n1")); return value;
    }
}
