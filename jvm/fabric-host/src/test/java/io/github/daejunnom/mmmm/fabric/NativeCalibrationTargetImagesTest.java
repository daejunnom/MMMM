package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.DoubleTag;
import net.minecraft.nbt.FloatTag;
import net.minecraft.nbt.IntTag;
import net.minecraft.nbt.NbtAccounter;
import net.minecraft.nbt.NbtIo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic ports/native codec fixtures do not issue a native ImagePair, ADMIN grant or game acceptance. */
final class NativeCalibrationTargetImagesTest {
    private static final String CASE = "int_add", FUNCTION = "mmmm_calibration:int_add";
    private static final String OBJECTIVE = "mcal" + ContractJson.sha256(CASE.getBytes(StandardCharsets.UTF_8)).substring(0, 11);
    private static final String STORAGE = "mmmm:calibration/" + CASE;
    private static final String OBJECTIVE_ID = "calibration-objective-" + OBJECTIVE;
    private static final String STORAGE_ID = "calibration-storage-" + ContractJson.sha256(STORAGE.getBytes(StandardCharsets.UTF_8));

    @Test void wholeOwnedTreesKeepUnknownNestedListArrayDataAndAllRawFloatingBitsWithoutKeepingLiveTags() throws Exception {
        CompoundTag root = nativeFixture(1); CompoundTag invocation = (CompoundTag) root.get("invocation");
        // D067 fixed 26.3 factories/decoder fold -0: one raw ABI compatibility input.
        @SuppressWarnings("removal")
        FloatTag negativeZero = new FloatTag(-0F);
        invocation.put("result", negativeZero);
        invocation.put("opaqueFloat", FloatTag.valueOf(Float.intBitsToFloat(0x7fc01234)));
        invocation.put("opaqueDouble", DoubleTag.valueOf(Double.longBitsToDouble(0x7ff8000000001234L)));
        var port = new Port(root);
        var first = scan(port); ObjectNode firstStorage = image(first.storageBytes());
        assertTrue(first.storageFullTargetKnown());
        assertEquals("present", firstStorage.path("presence").asText());
        ObjectNode originalInvocation = ContractJson.object(firstStorage.path("payload").path("invocation").path("nativeValueNbt"));
        assertEquals("80000000", floating(originalInvocation, "float_tag", "result"));
        assertEquals("7fc01234", floating(originalInvocation, "float_tag", "opaqueFloat"));
        assertEquals("7ff8000000001234", floating(originalInvocation, "double_tag", "opaqueDouble"));
        ObjectNode originalInputs = ContractJson.object(firstStorage.path("payload").path("inputs").path("nativeValueNbt"));
        String wholeInput = originalInputs.path("bytesHex").asText();
        for (String key : List.of("opaque", "bytes", "ints", "longs", "nested", "unfamiliar"))
            assertTrue(wholeInput.contains(HexFormat.of().formatHex(key.getBytes(StandardCharsets.UTF_8))), key);
        byte[] kept = first.storageBytes(); byte[] exported = first.storageBytes(); exported[0] ^= 1;
        assertArrayEquals(kept, first.storageBytes());
        invocation.put("opaqueFloat", FloatTag.valueOf(Float.intBitsToFloat(0x7fc05678)));
        invocation.put("opaqueDouble", DoubleTag.valueOf(Double.longBitsToDouble(0x7ff8000000005678L)));
        var changedBits = scan(port); ObjectNode changedInvocation = ContractJson.object(image(changedBits.storageBytes()).path("payload").path("invocation").path("nativeValueNbt"));
        // Native DataOutput canonicalizes NaN; the whole image sidecar must still distinguish the actual fields.
        assertEquals(originalInvocation.path("bytesHex"), changedInvocation.path("bytesHex"));
        assertNotEquals(first.storageSha256(), changedBits.storageSha256());
        assertEquals("7fc05678", floating(changedInvocation, "float_tag", "opaqueFloat"));
        assertEquals("7ff8000000005678", floating(changedInvocation, "double_tag", "opaqueDouble"));
        root.put("unownedRoot", IntTag.valueOf(18));
        assertEquals(changedBits.storageSha256(), scan(port).storageSha256()); // Selector owns exactly inputs/invocation, not the whole namespace.
        CompoundTag otherRoot = nativeFixture(2); otherRoot.put("invocation", invocation);
        assertNotEquals(changedBits.storageSha256(), scan(new Port(otherRoot)).storageSha256());
        assertArrayEquals(kept, first.storageBytes());
    }

    @Test void objectiveMetadataAndEveryHolderRemainInTheImageWhileUncachedAndAbsentStayDistinct() {
        var port = new Port(new CompoundTag()); var first = scan(port);
        assertTrue(first.objectiveFullTargetKnown()); assertTrue(first.storageFullTargetKnown());
        ObjectNode empty = image(first.storageBytes());
        assertEquals("absent", empty.path("presence").asText()); assertEquals("absent", empty.path("payload").path("inputs").path("presence").asText());
        assertEquals("absent", empty.path("payload").path("invocation").path("presence").asText());
        assertTrue(empty.path("payload").path("invocation").path("nativeValueNbt").isNull());
        port.objectivePayload.withArray("scores").add(ContractJson.newObject().put("holder", "unfamiliar-holder").put("value", -2147483648).put("locked", true));
        port.objectivePayload.put("nativeObjectiveNbt", "changed-factual-port-metadata");
        port.objectivePayload.withArray("displaySlots").add(ContractJson.newObject().put("name", "fixture-slot"));
        var changed = scan(port); assertNotEquals(first.objectiveSha256(), changed.objectiveSha256());
        assertEquals(2, image(changed.objectiveBytes()).path("payload").path("scores").size());
        port.root = null; var unknown = scan(port); ObjectNode rawUnknown = image(unknown.storageBytes());
        assertFalse(unknown.storageFullTargetKnown()); assertEquals("unknown", rawUnknown.path("status").asText());
        assertEquals("unknown", rawUnknown.path("presence").asText()); assertTrue(rawUnknown.path("payload").isNull());
        assertNotEquals(first.storageSha256(), unknown.storageSha256());
    }

    @Test void exactTypedFootprintAndOriginalCurrentControlAreRequiredBeforeNativeReadsAndKeepDualFailure() {
        var denied = context(); denied.withObject("scope").withArray("externalTargetIds").remove(1); var port = new Port(new CompoundTag());
        assertEquals("SCOPE_DENIED", assertThrows(ContractException.class, () -> NativeCalibrationTargetImages.scan(port, denied, selected(), () -> { })).code());
        assertEquals(0, port.reads.get());
        var bindings = bindings(); ContractJson.object(bindings.get(0)).put("objective", "arbitrary");
        assertThrows(ContractException.class, () -> NativeCalibrationTargetImages.select(CASE, FUNCTION, bindings));
        var wrongSubtree = bindings(); ContractJson.object(wrongSubtree.get(1)).withArray("ownedSubtrees").add("outside");
        assertThrows(ContractException.class, () -> NativeCalibrationTargetImages.select(CASE, FUNCTION, wrongSubtree));
        var currentFailure = new ContractException("CALIBRATION_STATE_CHANGED", "current native level unavailable");
        var detached = new Port(new CompoundTag()) { @Override public void checkCurrent() { throw currentFailure; } };
        assertSame(currentFailure, assertThrows(ContractException.class, () -> scan(detached))); assertEquals(0, detached.reads.get());
        var primary = new ContractException("NATIVE_READ_FAILED", "actual target read failed");
        var revoked = new ContractException("SOURCE_REVOKED", "actual source revoked"); var stopped = new AtomicBoolean();
        var failing = new Port(new CompoundTag()) {
            @Override public NativeCalibrationStateReader.StorageRead storage(String storage, NativeCalibrationStateReader.Checkpoint checkpoint) {
                reads.incrementAndGet(); stopped.set(true); throw primary;
            }
        };
        assertSame(primary, assertThrows(ContractException.class, () -> NativeCalibrationTargetImages.scan(failing, context(), selected(), () -> { if (stopped.get()) throw revoked; })));
        assertArrayEquals(new Throwable[]{revoked}, primary.getSuppressed()); assertEquals(2, failing.reads.get());
        assertSame(revoked, assertThrows(ContractException.class, () -> NativeCalibrationTargetImages.scan(port, context(), selected(), () -> { throw revoked; })));
        assertEquals(0, port.reads.get());
    }

    @Test void boundedWholeCodecRejectsExcessiveDepthAndImageSizeAndKeepsCheckpointFailure() {
        var deep = new CompoundTag(); CompoundTag at = deep;
        for (int depth = 0; depth < 65; depth++) { var child = new CompoundTag(); at.put("child", child); at = child; }
        assertThrows(ContractException.class, () -> NativeTargets.encodeNativeTag(deep, () -> { }));
        var floatingBoundary = new CompoundTag();
        for (int index = 0; index < 1023; index++) floatingBoundary.put("f" + Integer.toString(10_000 + index).substring(1), FloatTag.valueOf(1F));
        assertEquals(65_473, ContractJson.canonical(NativeTargets.encodeNativeTag(floatingBoundary, () -> { }).path("rawFloatingBits")).length);
        floatingBoundary.put("f1023", FloatTag.valueOf(1F));
        // The next array is 65,537 bytes although its individual entries total less than 64 KiB.
        assertThrows(ContractException.class, () -> NativeTargets.encodeNativeTag(floatingBoundary, () -> { }));
        var port = new Port(new CompoundTag()); port.objectivePayload.put("beyond-image-budget", "x".repeat(NativeCalibrationTargetImages.MAX_TARGET_BYTES));
        assertEquals("CALIBRATION_TARGET_IMAGE_LIMIT", assertThrows(ContractException.class, () -> scan(port)).code());
        var stopped = new ContractException("ORIGINAL_CANCELLED", "original cancelled"); var calls = new AtomicInteger();
        assertSame(stopped, assertThrows(ContractException.class, () -> NativeTargets.encodeNativeTag(new CompoundTag(), () -> { if (calls.incrementAndGet() >= 2) throw stopped; })));
    }

    private static class Port implements NativeCalibrationTargetImages.ReadPort {
        CompoundTag root;
        final AtomicInteger reads = new AtomicInteger();
        final ObjectNode objectivePayload = ContractJson.newObject();
        Port(CompoundTag root) {
            this.root = root; objectivePayload.put("nativeObjectiveNbt", "factual-port-fixture-only");
            objectivePayload.putArray("scores").add(ContractJson.newObject().put("holder", "#ok").put("value", 17).put("locked", false)); objectivePayload.putArray("displaySlots");
        }
        @Override public ObjectNode objective(String name, NativeCalibrationStateReader.Checkpoint checkpoint) {
            assertEquals(OBJECTIVE, name); reads.incrementAndGet(); ObjectNode value = ContractJson.newObject().put("format", "mmmm.native.target/1");
            value.set("selector", ContractJson.newObject().put("kind", "objective").put("objective", OBJECTIVE));
            value.put("status", "known").put("presence", "present").put("membershipScope", "current_native_scoreboard")
                    .put("captureScope", "native_objective_and_all_scores").put("coverage", "full_target").putNull("reason");
            value.set("payload", objectivePayload.deepCopy()); return value;
        }
        @Override public NativeCalibrationStateReader.StorageRead storage(String name, NativeCalibrationStateReader.Checkpoint checkpoint) {
            assertEquals(STORAGE, name); reads.incrementAndGet();
            return new NativeCalibrationStateReader.StorageRead(root, root == null ? NativeCalibrationStateReader.Unknown.STORAGE_NOT_CACHED : null);
        }
        @Override public void checkCurrent() { }
    }
    private static NativeCalibrationTargetImages.RawPair scan(Port port) { return NativeCalibrationTargetImages.scan(port, context(), selected(), () -> { }); }
    private static NativeCalibrationTargetImages.ReadonlySelection selected() { return NativeCalibrationTargetImages.select(CASE, FUNCTION, bindings()); }
    private static JsonNode bindings() {
        var array = ContractJson.newObject().putArray("bindings");
        array.add(ContractJson.newObject().put("targetId", OBJECTIVE_ID).put("kind", "objective").put("objective", OBJECTIVE));
        ObjectNode storage = ContractJson.newObject().put("targetId", STORAGE_ID).put("kind", "owned_storage").put("storage", STORAGE);
        storage.putArray("ownedSubtrees").add("inputs").add("invocation"); array.add(storage); return array;
    }
    private static ObjectNode context() { ObjectNode context = ContractJson.newObject(); context.putObject("scope").putArray("externalTargetIds").add(OBJECTIVE_ID).add(STORAGE_ID); return context; }
    private static ObjectNode image(byte[] bytes) { return ContractJson.object(ContractJson.parse(bytes)); }
    private static String floating(ObjectNode encoded, String kind, String key) {
        for (JsonNode value : encoded.path("rawFloatingBits"))
            if (kind.equals(value.path("kind").asText()) && value.path("path").equals(ContractJson.newObject().putArray("path").add(ContractJson.newObject().put("key", key)))) return value.path("bits").asText();
        throw new AssertionError("Missing actual floating field " + key);
    }
    /** Small actual native decoder input, including unknown compound/list/primitive arrays. */
    private static CompoundTag nativeFixture(int marker) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(bytes)) {
            out.writeByte(10); out.writeUTF(""); out.writeByte(10); out.writeUTF("inputs");
            out.writeByte(3); out.writeUTF("n0"); out.writeInt(17);
            out.writeByte(10); out.writeUTF("opaque");
            out.writeByte(7); out.writeUTF("bytes"); out.writeInt(3); out.write(new byte[]{(byte) marker, 2, 3});
            out.writeByte(11); out.writeUTF("ints"); out.writeInt(2); out.writeInt(Integer.MIN_VALUE); out.writeInt(Integer.MAX_VALUE);
            out.writeByte(12); out.writeUTF("longs"); out.writeInt(2); out.writeLong(Long.MIN_VALUE); out.writeLong(Long.MAX_VALUE);
            out.writeByte(9); out.writeUTF("nested"); out.writeByte(10); out.writeInt(1);
            out.writeByte(8); out.writeUTF("unfamiliar"); out.writeUTF("kept"); out.writeByte(0);
            out.writeByte(0); out.writeByte(0);
            out.writeByte(10); out.writeUTF("invocation"); out.writeByte(3); out.writeUTF("unknownCounter"); out.writeInt(-19); out.writeByte(0); out.writeByte(0);
        }
        try (var input = new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            CompoundTag value = NbtIo.read(input, NbtAccounter.create(64 * 1024)); assertEquals(-1, input.read()); return value;
        }
    }
}
