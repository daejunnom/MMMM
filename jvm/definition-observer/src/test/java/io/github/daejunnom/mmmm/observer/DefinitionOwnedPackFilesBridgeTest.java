// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Pure held-root boundary fixtures. Existing definition frames contain neither
 * retained close facts nor actual Java Throwable references. These checks issue
 * no producer token, native root, global reference, source or permission proof.
 */
final class DefinitionOwnedPackFilesBridgeTest {
    @Test void emptyAnchorPreservesOnlyFourActualObjectsAndCannotEnterTheNativeBoundary() throws Exception {
        Object server = new Object(), attempt = new Object(), invocation = new Object(), bundle = new Object();
        var locator = DefinitionOwnedPackFilesBridge.newRootAnchor(server, attempt, invocation, bundle);
        Object[] originals = {server, attempt, invocation, bundle};
        String[] names = {"nativeServer", "nativeAttempt", "nativeInvocation", "nativeBundle"};
        for (int index = 0; index < names.length; index++) {
            var getter = locator.getClass().getDeclaredMethod(names[index]);
            assertTrue(Modifier.isPrivate(getter.getModifiers())); getter.setAccessible(true);
            assertSame(originals[index], getter.invoke(locator));
        }
        assertTrue(Modifier.isFinal(locator.getClass().getModifiers()));
        assertEquals(4, locator.getClass().getDeclaredFields().length);
        for (var field : locator.getClass().getDeclaredFields()) {
            assertEquals(Object.class, field.getType()); assertTrue(Modifier.isFinal(field.getModifiers()));
        }
        for (var constructor : locator.getClass().getDeclaredConstructors()) assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.observeHeldRoot(locator));
        assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.retireHeldRoot(locator));
        assertThrows(NullPointerException.class, () -> DefinitionOwnedPackFilesBridge.newRootAnchor(null, attempt, invocation, bundle));
    }

    @Test void identityAndCloseFactsKeepTheirActualOsGradeWithoutCreatingAHandle() throws IOException {
        var windows = DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(3, 4, 1, 1, 6, 0, 0, 0, null)}, 3);
        assertEquals(3, windows.operation()); assertEquals("complete", windows.state());
        assertEquals("windows_create_handle", windows.evidenceGrade()); assertEquals("same", windows.identity());
        assertEquals(6, windows.pins()); assertEquals(0, windows.closed());
        var posix = DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(3, 3, 2, 2, 4, 0, 0, 0, null)}, 3);
        assertEquals("published_partial", posix.state()); assertEquals("posix_cooperative", posix.evidenceGrade());
        assertEquals("different", posix.identity());
        var released = DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 6, 2, 0, 4, 2, 1, 1, null)}, 4);
        assertEquals("reference_released", released.state()); assertEquals("not_observed", released.identity());
        assertEquals(4, released.pins()); assertEquals(2, released.closed()); assertEquals(1, released.shared()); assertEquals(1, released.uncertain());
        assertFalse(Arrays.stream(released.getClass().getDeclaredFields()).anyMatch(field -> field.getType() == DefinitionOwnedPackFilesBridge.RootAnchor.class));
    }

    @Test void failedFreshCheckpointKeepsCloseMetadataAndTheActualLifetimeFailure() throws IOException {
        var original = new IllegalStateException("fixture-original-checkpoint");
        byte[] failure;
        try (var bytes = new ByteArrayOutputStream(); var out = new DataOutputStream(bytes)) {
            out.writeByte(7); out.writeByte(6); out.writeShort(0);
            out.writeByte(9); out.writeByte(2);
            byte[] operation = "GetModuleHandleExW".getBytes(StandardCharsets.US_ASCII);
            out.writeByte(operation.length); out.write(operation);
            out.writeByte(1); out.writeInt(0xC0000001); out.writeByte(1); out.writeInt(5);
            failure = bytes.toByteArray();
        }
        var actual = assertThrows(DefinitionOwnedPackFilesBridge.NativeFailure.class,
                () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 7, 1, 0, 5, 2, 2, 1, failure), original}, 4));
        assertEquals("ORIGINAL_CHECKPOINT", actual.code()); assertSame(original, actual.getCause());
        assertTrue(actual.effectsMayExist()); assertNull(actual.completedReceipt());
        assertNotNull(actual.completedHeldReceipt()); assertEquals("close_uncertain", actual.completedHeldReceipt().state());
        assertEquals(1, actual.completedHeldReceipt().uncertain());
        var lifetime = assertInstanceOf(DefinitionOwnedPackFilesBridge.NativeFailure.class, actual.getSuppressed()[0]);
        assertEquals("NATIVE_LIFETIME_UNAVAILABLE", lifetime.code());
        assertEquals("native_failure", lifetime.nativeLifetime().kind()); assertEquals("GetModuleHandleExW", lifetime.nativeLifetime().operation());
        assertEquals(Integer.valueOf(0xC0000001), lifetime.nativeLifetime().status()); assertEquals(Integer.valueOf(5), lifetime.nativeLifetime().nativeCode());
    }

    @Test void allRetentionStatesAndFiniteCountsRemainMetadataOnly() throws IOException {
        String[] states = {"reserved", "held_unpublished", "published_partial", "complete", "retiring", "reference_released", "close_uncertain", "vm_owned"};
        for (int state = 1; state <= states.length; state++) {
            var actual = DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, state, 0, 0, 66, 64, 1, 1, null)}, 4);
            assertEquals(states[state - 1], actual.state()); assertEquals("unknown", actual.evidenceGrade()); assertEquals(66, actual.pins());
            assertEquals(64, actual.closed()); assertEquals(1, actual.shared()); assertEquals(1, actual.uncertain());
        }
    }

    @Test void failureBeforeNativeLookupPreservesItsOriginalCauseWithoutInventingRootFacts() throws IOException {
        var checkpoint = new IllegalStateException("original-before-native-lookup");
        var actual = assertThrows(DefinitionOwnedPackFilesBridge.NativeFailure.class,
                () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 0, 0, 0, 0, 0, 0, 0, new byte[] {6, 0, 0}), checkpoint}, 4));
        assertEquals("ORIGINAL_CHECKPOINT", actual.code()); assertSame(checkpoint, actual.getCause());
        assertEquals("unknown", actual.completedHeldReceipt().state()); assertEquals(0, actual.completedHeldReceipt().pins());
        assertEquals("not_observed", actual.completedHeldReceipt().identity());
        for (byte[] invalid : new byte[][] {
                frame(4, 0, 0, 0, 0, 0, 0, 0, null), frame(4, 0, 1, 0, 0, 0, 0, 0, new byte[] {8}),
                frame(4, 0, 0, 1, 0, 0, 0, 0, new byte[] {8}), frame(4, 0, 0, 0, 1, 0, 0, 0, new byte[] {8}),
                frame(4, 7, 0, 0, 67, 0, 0, 0, new byte[] {8}), frame(4, 7, 0, 0, 1, 1, 1, 0, new byte[] {8})}) {
            assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {invalid}, 4));
        }
    }

    @Test void closeFailurePreservesTheActualStagePinAndUnderlyingNativeIoFact() throws IOException {
        byte[] tree = {10, 2, 1, 0, 3, 5, 1, 0, 0, 0, 5, 0};
        var actual = assertThrows(DefinitionOwnedPackFilesBridge.NativeFailure.class,
                () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 7, 2, 0, 4, 2, 1, 1, tree)}, 4));
        assertEquals("NATIVE_RETAINED_CLOSE", actual.code()); assertEquals("native_close", actual.retainedClose().stage());
        assertEquals(Integer.valueOf(3), actual.retainedClose().pin());
        var io = assertInstanceOf(DefinitionOwnedPackFilesBridge.NativeFailure.class, actual.getCause());
        assertEquals("NATIVE_IO", io.code()); assertEquals(Integer.valueOf(5), io.nativeError());
        assertEquals("close_uncertain", actual.completedHeldReceipt().state());
        for (byte[] invalid : new byte[][] {{10, 0, 0, 5, 0, 0}, {10, 1, 2, 5, 0, 0}, {10, 1, 0, 8}, {10, 2, 1, 0, 66, 5, 0, 0}}) {
            assertThrows(IllegalStateException.class,
                    () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 7, 0, 0, 0, 0, 0, 0, invalid)}, 4));
        }
    }

    @Test void heldFailureTreeUsesItsSeparateBoundAndRejectsOversizedOrInvalidReferences() throws IOException {
        byte[] deepestValid = postChain(255);
        var actual = assertThrows(DefinitionOwnedPackFilesBridge.NativeFailure.class,
                () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 8, 0, 0, 0, 0, 0, 0, deepestValid)}, 4));
        assertEquals("NATIVE_PANIC", actual.code());
        assertThrows(IllegalStateException.class,
                () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 8, 0, 0, 0, 0, 0, 0, postChain(256))}, 4));
        assertThrows(IllegalStateException.class,
                () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {frame(4, 7, 0, 0, 0, 0, 0, 0, new byte[] {6, 0, 1})}, 4));
        Object[] tooMany = new Object[258]; tooMany[0] = frame(4, 6, 0, 0, 0, 0, 0, 0, null);
        assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.decodeHeld(tooMany, 4));
    }

    @Test void malformedHeldHeadersTrailingBytesAndUnboundedFramesCannotProduceFacts() throws IOException {
        byte[] valid = frame(3, 4, 2, 1, 4, 0, 0, 0, null);
        for (byte[] invalid : new byte[][] {Arrays.copyOf(valid, valid.length - 1), Arrays.copyOf(valid, valid.length + 1), new byte[65537]}) {
            assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {invalid}, 3));
        }
        for (int offset : new int[] {0, 8, 9, 10, 11, 20}) {
            byte[] invalid = valid.clone(); invalid[offset] = (byte) 0xff;
            assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {invalid}, 3));
        }
        assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {valid}, 4));
        assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {valid}, 1));
        assertThrows(IllegalStateException.class, () -> DefinitionOwnedPackFilesBridge.decodeHeld(new Object[] {valid, new Object()}, 3));
    }

    private static byte[] frame(int operation, int state, int grade, int identity, int pins, int closed, int shared, int uncertain,
                                byte[] failure) throws IOException {
        try (var bytes = new ByteArrayOutputStream(); var out = new DataOutputStream(bytes)) {
            out.write("MMMMPKH1".getBytes(StandardCharsets.US_ASCII)); out.writeByte(operation); out.writeByte(state);
            out.writeByte(grade); out.writeByte(identity); out.writeShort(pins); out.writeShort(closed); out.writeShort(shared); out.writeShort(uncertain);
            out.writeByte(failure == null ? 0 : 1); if (failure != null) out.write(failure);
            return bytes.toByteArray();
        }
    }
    private static byte[] postChain(int depth) {
        byte[] bytes = new byte[depth * 2 + 1]; Arrays.fill(bytes, 0, depth, (byte) 7); Arrays.fill(bytes, depth, bytes.length, (byte) 8); return bytes;
    }
}
