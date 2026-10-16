// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Pure boundary-codec checks. These fixtures issue no native or runtime source proof. */
final class DefinitionObserverBridgeTest {
    @Test void immutableObservationPreservesExactOriginalClassAndNativeBuffers() throws Exception {
        byte[] input = ordinary(DefinitionObserverBridgeTest.class, 1, 0, 0, new byte[] {(byte) 0xb1});
        var result = DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, input);
        assertSame(DefinitionObserverBridgeTest.class, result.actualClass());
        assertFalse(result.hidden()); assertEquals(17, result.classIdentity());
        assertEquals(19, result.generation()); assertEquals(23, result.attempt()); assertEquals(29, result.issuerEpoch());
        byte[] expected = input.clone(); input[0] = 0;
        assertArrayEquals(expected, result.envelope());
        byte[] observed = result.terminalObservedBytes(); observed[0] = 0;
        assertEquals(0xCA, Byte.toUnsignedInt(result.terminalObservedBytes()[0]));
        byte[] code = result.methods().getFirst().bytecodes(); code[0] = 0;
        assertEquals(0xb1, Byte.toUnsignedInt(result.methods().getFirst().bytecodes()[0]));
        assertThrows(UnsupportedOperationException.class, () -> result.methods().clear());
    }

    @Test void mismatchedActualClassAndUnpreparedObservationAreRejected() throws Exception {
        byte[] input = ordinary(DefinitionObserverBridgeTest.class, 1, 0, 0, new byte[] {(byte) 0xb1});
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(String.class, input));
        byte[] unprepared = input.clone(); unprepared[9] = 0;
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, unprepared));
        byte[] unknownFlags = input.clone(); unknownFlags[9] = 5;
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, unknownFlags));
    }

    @Test void hiddenKindCannotPromoteAnOrdinaryClassOrOrdinaryBytes() throws Exception {
        byte[] input = ordinary(DefinitionObserverBridgeTest.class, 1, 0, 0, new byte[] {(byte) 0xb1}); input[8] = 2;
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, input));
    }

    @Test void trailingTruncatedAndUnsignedOversizeFramesAreRejected() throws Exception {
        byte[] input = ordinary(DefinitionObserverBridgeTest.class, 1, 0, 0, new byte[] {(byte) 0xb1});
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, Arrays.copyOf(input, input.length - 1)));
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, Arrays.copyOf(input, input.length + 1)));
        byte[] hugeName = input.clone(); Arrays.fill(hugeName, 44, 48, (byte) 0xff);
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, hugeName));
        byte[] oversize = new byte[8 * 1024 * 1024 + 1];
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, oversize));
    }

    @Test void zeroNativeIdentityTokenIsRejected() throws Exception {
        byte[] input = ordinary(DefinitionObserverBridgeTest.class, 1, 0, 0, new byte[] {(byte) 0xb1}); Arrays.fill(input, 12, 20, (byte) 0);
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, input));
    }

    @Test void duplicateMethodIdentityAndInconsistentCodeKindsAreRejected() throws Exception {
        byte[] duplicate = ordinary(DefinitionObserverBridgeTest.class, 2, 0, 0, new byte[] {(byte) 0xb1});
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, duplicate));
        for (byte[] invalid : new byte[][] {
                ordinary(DefinitionObserverBridgeTest.class, 1, 0x0100, 0, new byte[] {(byte) 0xb1}),
                ordinary(DefinitionObserverBridgeTest.class, 1, 0, 1, new byte[0]),
                ordinary(DefinitionObserverBridgeTest.class, 1, 0x0400, 2, new byte[] {(byte) 0xb1}),
                ordinary(DefinitionObserverBridgeTest.class, 1, 0x0500, 1, new byte[0])}) {
            assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, invalid));
        }
    }

    @Test void nativeAndAbstractMethodsStayExplicitWithoutInventedBytecodes() throws Exception {
        var nativeMethod = DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class,
                ordinary(DefinitionObserverBridgeTest.class, 1, 0x0100, 1, new byte[0]));
        assertEquals(1, nativeMethod.methods().getFirst().codeKind());
        assertEquals(0, nativeMethod.methods().getFirst().bytecodes().length);
        var abstractMethod = DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class,
                ordinary(DefinitionObserverBridgeTest.class, 1, 0x0400, 2, new byte[0]));
        assertEquals(2, abstractMethod.methods().getFirst().codeKind());
    }

    @Test void nonReferenceSubjectsCannotAcquireAnExecutableViewWithoutTheNativeProducer() {
        assertThrows(NullPointerException.class, () -> DefinitionObserverBridge.observeCurrentExecutable(null));
        assertTrue(DefinitionObserverBridge.observeCurrentExecutable(int.class).isEmpty());
        assertTrue(DefinitionObserverBridge.observeCurrentExecutable(String[].class).isEmpty());
    }

    @Test void currentComparisonRequiresActualLoaderIdentityAndTheWholeOriginalObservation() throws Exception {
        // These decoded frames exercise comparison only; none can construct an issuer-acquired view.
        byte[] frame = ordinary(getClass(), 1, 0, 0, new byte[] {(byte) 0xb1});
        var original = DefinitionObserverBridge.decode(getClass(), frame);
        var copy = DefinitionObserverBridge.decode(getClass(), frame.clone());
        ClassLoader loader = getClass().getClassLoader();
        assertTrue(DefinitionObserverBridge.sameExecutableObservation(original, loader, copy, loader));
        assertFalse(DefinitionObserverBridge.sameExecutableObservation(original, loader, copy, null));
        assertFalse(DefinitionObserverBridge.sameExecutableObservation(original, null, copy, null));
        assertFalse(DefinitionObserverBridge.sameExecutableObservation(original, loader, copy, new ClassLoader(loader) { }));
        byte[] changedGeneration = frame.clone(); java.nio.ByteBuffer.wrap(changedGeneration).putLong(20, 20);
        var changed = DefinitionObserverBridge.decode(getClass(), changedGeneration);
        assertFalse(DefinitionObserverBridge.sameExecutableObservation(original, loader, changed, loader));
        var changedCode = DefinitionObserverBridge.decode(getClass(), ordinary(getClass(), 1, 0, 0, new byte[] {0, (byte) 0xb1}));
        assertFalse(DefinitionObserverBridge.sameExecutableObservation(original, loader, changedCode, loader));
        var differentClass = DefinitionObserverBridge.decode(String.class, ordinary(String.class, 1, 0, 0, new byte[] {(byte) 0xb1}));
        assertFalse(DefinitionObserverBridge.sameExecutableObservation(original, loader, differentClass, String.class.getClassLoader()));
    }

    @Test void canonicalJniModifiedUtf8PreservesNulAndSupplementaryCodeUnits() throws Exception {
        byte[] rawName = new byte[] {'x', (byte) 0xc0, (byte) 0x80,
                (byte) 0xed, (byte) 0xa0, (byte) 0xbd, (byte) 0xed, (byte) 0xb8, (byte) 0x80};
        byte[] frame = ordinaryWithMetadata(rawName, 0, 0);
        var observed = DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, frame);
        assertEquals("x\u0000\ud83d\ude00", observed.methods().getFirst().name());
        assertArrayEquals(frame, observed.envelope());
    }

    @Test void malformedOverlongAndStandardFourByteUtf8AreRejected() throws Exception {
        for (byte[] name : new byte[][] {
                {0}, {(byte) 0xc1, (byte) 0x80}, {(byte) 0xc0, (byte) 0x81},
                {(byte) 0xe0, (byte) 0x80, (byte) 0x80}, {(byte) 0xc2},
                {(byte) 0xf0, (byte) 0x9f, (byte) 0x98, (byte) 0x80}}) {
            byte[] frame = ordinaryWithMetadata(name, 0, 0);
            assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, frame));
        }
    }

    @Test void ordinaryDefinitionCannotCarryHiddenInitializationOrLookupClaims() throws Exception {
        for (byte[] frame : new byte[][] {
                ordinaryWithMetadata(new byte[] {'r', 'u', 'n'}, 1, 0),
                ordinaryWithMetadata(new byte[] {'r', 'u', 'n'}, 0, 37)}) {
            assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionObserverBridgeTest.class, frame));
        }
    }

    @Test void hiddenRecipeRemainsDistinctFromOrdinaryTerminalDefinitionBytes() throws Exception {
        byte[] recipe;
        try (var stream = DefinitionStartupProbe.class.getResourceAsStream("DefinitionStartupProbe.class")) {
            assertNotNull(stream);
            recipe = stream.readNBytes(64 * 1024 + 1);
            assertTrue(recipe.length > 0 && recipe.length <= 64 * 1024);
            assertEquals(-1, stream.read());
        }
        Class<?> hiddenClass = MethodHandles.lookup().defineHiddenClass(recipe, false).lookupClass();
        // Native IDs and snapshots below are codec fixtures. Defining this own
        // test Class does not establish a producer-issued definition receipt.
        byte[] frame = hidden(hiddenClass, recipe);
        var observation = DefinitionObserverBridge.decode(hiddenClass, frame);
        assertSame(hiddenClass, observation.actualClass());
        assertTrue(observation.hidden()); assertTrue(observation.controlledRecipeInterposition());
        assertEquals(0, observation.terminalObservedBytes().length);
        assertArrayEquals(recipe, observation.hiddenInputBytes());
        assertEquals(2, observation.hiddenFlags()); assertFalse(observation.hiddenInitialize());
        assertEquals(41, observation.lookupClassIdentity());
        assertEquals(DefinitionStartupProbe.class.getName(), observation.hiddenRequestedName());
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(DefinitionStartupProbe.class, frame));
        byte[] unprotectedRecipe = frame.clone(); unprotectedRecipe[9] = 1;
        assertThrows(IllegalArgumentException.class, () -> DefinitionObserverBridge.decode(hiddenClass, unprotectedRecipe));
    }

    private static byte[] ordinary(Class<?> subject, int methodCount, int modifiers, int codeKind, byte[] code) throws IOException {
        return ordinary(subject, methodCount, modifiers, codeKind, code,
                new byte[] {'r', 'u', 'n'}, 0, 0);
    }
    private static byte[] ordinaryWithMetadata(byte[] name, int hiddenInitialize, long lookupId) throws IOException {
        return ordinary(DefinitionObserverBridgeTest.class, 1, 0, 0, new byte[] {(byte) 0xb1},
                name, hiddenInitialize, lookupId);
    }
    private static byte[] ordinary(Class<?> subject, int methodCount, int modifiers, int codeKind, byte[] code,
            byte[] methodName, int hiddenInitialize, long lookupId) throws IOException {
        var output = new ByteArrayOutputStream(); var writer = new DataOutputStream(output);
        writer.write("MMMMDEF1".getBytes(StandardCharsets.US_ASCII)); writer.writeByte(1); writer.writeByte(1); writer.writeShort(0);
        writer.writeLong(17); writer.writeLong(19); writer.writeLong(23); writer.writeLong(29);
        sized(writer, subject.getName().getBytes(StandardCharsets.UTF_8));
        sized(writer, new byte[] {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE}); sized(writer, new byte[0]); writer.writeInt(0);
        writer.writeByte(hiddenInitialize); writer.writeByte(0); writer.writeShort(0); writer.writeLong(lookupId); writer.writeLong(31);
        sized(writer, new byte[0]);
        writer.writeInt(2); sized(writer, new byte[] {1, 0, 1, 65}); writer.writeInt(methodCount);
        for (int index = 0; index < methodCount; index++) {
            sized(writer, methodName); sized(writer, "()V".getBytes(StandardCharsets.UTF_8));
            writer.writeInt(modifiers); writer.writeByte(codeKind); sized(writer, code);
        }
        writer.flush(); return output.toByteArray();
    }
    private static byte[] hidden(Class<?> subject, byte[] recipe) throws IOException {
        var output = new ByteArrayOutputStream(); var writer = new DataOutputStream(output);
        writer.write("MMMMDEF1".getBytes(StandardCharsets.US_ASCII)); writer.writeByte(2); writer.writeByte(3); writer.writeShort(0);
        writer.writeLong(17); writer.writeLong(19); writer.writeLong(23); writer.writeLong(29);
        sized(writer, subject.getName().getBytes(StandardCharsets.UTF_8)); sized(writer, new byte[0]); sized(writer, recipe);
        writer.writeInt(2); writer.writeByte(0); writer.writeByte(0); writer.writeShort(0); writer.writeLong(41); writer.writeLong(31);
        sized(writer, DefinitionStartupProbe.class.getName().getBytes(StandardCharsets.UTF_8));
        writer.writeInt(2); sized(writer, new byte[] {1, 0, 1, 65}); writer.writeInt(1);
        sized(writer, new byte[] {'<', 'i', 'n', 'i', 't', '>'}); sized(writer, new byte[] {'(', ')', 'V'});
        writer.writeInt(0); writer.writeByte(0); sized(writer, new byte[] {(byte) 0xb1});
        writer.flush(); return output.toByteArray();
    }
    private static void sized(DataOutputStream writer, byte[] value) throws IOException { writer.writeInt(value.length); writer.write(value); }
}
