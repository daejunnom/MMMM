// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Descriptive codec fixtures only: no native definition, target or handler proof is issued. */
final class DefinitionObserverForwarderTest {
    private static final String PROBE = "io/github/daejunnom/mmmm/observer/DefinitionStartupProbe";

    @Test void originalHiddenIdentityAndRawFrameRemainImmutable() throws Exception {
        var original = original();
        byte[] frame = frame(4, 1, 2, PROBE, false, false);
        var match = DefinitionObserverBridge.decodeForwarder(original, frame);
        assertSame(original, match.source());
        assertEquals(5, match.targetClassIdentity());
        assertEquals(6, match.targetGeneration());
        assertEquals("java/lang/Runnable", match.interfaceName());
        assertEquals("run", match.samName());
        assertEquals("()V", match.targetDescriptor());
        assertEquals(2, match.targetClassStatus());
        byte[] retained = match.envelope();
        Arrays.fill(frame, (byte) 0);
        Arrays.fill(match.envelope(), (byte) 0);
        assertArrayEquals(retained, match.envelope());
        assertThrows(UnsupportedOperationException.class, () -> match.referencedClasses().clear());
    }

    @Test void wrongSourceEpochGenerationAndRecipeNameAreRejected() throws Exception {
        var original = original();
        assertThrows(IllegalArgumentException.class,
                () -> DefinitionObserverBridge.decodeForwarder(original, frame(9, 1, 2, PROBE, false, false)));
        assertThrows(IllegalArgumentException.class,
                () -> DefinitionObserverBridge.decodeForwarder(original, frame(4, 9, 2, PROBE, false, false)));
        assertThrows(IllegalArgumentException.class,
                () -> DefinitionObserverBridge.decodeForwarder(original, frame(4, 1, 9, PROBE, false, false)));
        assertThrows(IllegalArgumentException.class,
                () -> DefinitionObserverBridge.decodeForwarder(original, frame(4, 1, 2, "other/Probe", false, false)));
    }

    @Test void malformedUtf8DuplicateReferencesAndTrailingBytesAreRejected() throws Exception {
        var original = original();
        assertThrows(IllegalArgumentException.class,
                () -> DefinitionObserverBridge.decodeForwarder(original, frame(4, 1, 2, PROBE, true, false)));
        assertThrows(IllegalArgumentException.class,
                () -> DefinitionObserverBridge.decodeForwarder(original, frame(4, 1, 2, PROBE, false, true)));
        byte[] valid = frame(4, 1, 2, PROBE, false, false);
        byte[] extra = Arrays.copyOf(valid, valid.length + 1);
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decodeForwarder(original, extra));
        assertThrows(IllegalArgumentException.class,
                () -> DefinitionObserverBridge.decodeForwarder(original, Arrays.copyOf(valid, valid.length - 1)));
    }

    private static DefinitionObserverBridge.ObservedDefinition original() throws Exception {
        byte[] input;
        try (var stream = DefinitionStartupProbe.class.getResourceAsStream("DefinitionStartupProbe.class")) {
            if (stream == null) throw new IllegalStateException("OWN_PROBE_INPUT_MISSING");
            input = stream.readNBytes(65537);
        }
        if (input.length == 0 || input.length > 65536) throw new IllegalStateException("OWN_PROBE_INPUT_INVALID");
        Class<?> hidden = MethodHandles.lookup().defineHiddenClass(input, false).lookupClass();
        var bytes = new ByteArrayOutputStream();
        try (var writer = new DataOutputStream(bytes)) {
            writer.writeBytes("MMMMDEF1"); writer.writeByte(2); writer.writeByte(3); writer.writeShort(0);
            writer.writeLong(1); writer.writeLong(2); writer.writeLong(3); writer.writeLong(4);
            sized(writer, hidden.getName().getBytes(StandardCharsets.UTF_8));
            sized(writer, new byte[0]); sized(writer, input);
            writer.writeInt(2); writer.writeByte(0); writer.writeByte(0); writer.writeShort(0);
            writer.writeLong(7); writer.writeLong(0); sized(writer, PROBE.getBytes(StandardCharsets.UTF_8));
            writer.writeInt(1); sized(writer, new byte[] {1}); writer.writeInt(1);
            sized(writer, "identity".getBytes(StandardCharsets.UTF_8)); sized(writer, "(I)I".getBytes(StandardCharsets.UTF_8));
            writer.writeInt(0x0008); writer.writeByte(0); sized(writer, new byte[] {(byte) 0xac});
        }
        return DefinitionObserverBridge.decode(hidden, bytes.toByteArray());
    }

    private static byte[] frame(long epoch, long identity, long generation, String recipe,
            boolean malformed, boolean duplicate) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var writer = new DataOutputStream(bytes)) {
            writer.writeBytes("MMMMSAM1"); writer.writeShort(1); writer.writeShort(0);
            writer.writeLong(epoch); writer.writeLong(identity); writer.writeLong(generation);
            writer.writeLong(5); writer.writeLong(6); writer.writeInt(2);
            for (String text : new String[] {recipe, "java/lang/Runnable", "run", "()V", PROBE, "run", "()V"}) {
                sized(writer, malformed && text.equals("run") ? new byte[] {(byte) 0xc0, (byte) 0x80}
                        : text.getBytes(StandardCharsets.UTF_8));
            }
            writer.writeByte(0); writer.writeByte(0); writer.writeShort(0); writer.writeInt(2);
            sized(writer, "java/lang/Runnable".getBytes(StandardCharsets.UTF_8));
            sized(writer, (duplicate ? "java/lang/Runnable" : PROBE).getBytes(StandardCharsets.UTF_8));
        }
        return bytes.toByteArray();
    }

    private static void sized(DataOutputStream writer, byte[] value) throws Exception {
        writer.writeInt(value.length); writer.write(value);
    }
}
