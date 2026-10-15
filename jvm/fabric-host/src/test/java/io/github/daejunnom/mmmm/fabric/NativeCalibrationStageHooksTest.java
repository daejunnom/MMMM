package io.github.daejunnom.mmmm.fabric;

import com.mojang.brigadier.context.CommandContext;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Callsite ownership/error tests only; no game, JNI view, ready or actual run is manufactured. */
final class NativeCalibrationStageHooksTest {
    @Test void outsideScopeInvokesOriginalOnceAndKeepsNegativeReturn() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        assertEquals(-7, NativeCalibrationStageHooks.nativeHandler(context -> { calls.incrementAndGet(); return -7; }, null));
        NativeCalibrationStageHooks.nativeCustom(new Object(), new Object(), new Object(), true, calls::incrementAndGet);
        assertEquals(2, calls.get());
    }
    @Test void originalHandlerFailurePreservesFollowingCurrentFailureAndScopeRetires() {
        RuntimeException primary = new IllegalStateException("original"); Error post = new AssertionError("post");
        var listener = new Listener() {
            @Override public void afterHandler(Object handler, CommandContext<?> context, Integer result, Throwable failure) {
                assertSame(primary, failure); assertNull(result); throw post;
            }
        };
        try (var scope = NativeCalibrationStageHooks.open(listener)) {
            assertSame(primary, assertThrows(RuntimeException.class,
                    () -> NativeCalibrationStageHooks.nativeHandler(context -> { throw primary; }, null)));
            assertArrayEquals(new Throwable[] {post}, primary.getSuppressed());
        }
        assertDoesNotThrow(() -> assertEquals(0, NativeCalibrationStageHooks.nativeHandler(context -> 0, null)));
    }
    @Test void failedCustomCallPreservesPostErrorWithoutCallingAgain() {
        RuntimeException primary = new IllegalArgumentException("original"); RuntimeException post = new IllegalStateException("post");
        AtomicInteger calls = new AtomicInteger();
        var listener = new Listener() {
            @Override public void afterCustom(Object receiver, Object chain, Object frame, boolean modifier, Throwable failure) {
                assertSame(primary, failure); throw post;
            }
        };
        try (var scope = NativeCalibrationStageHooks.open(listener)) {
            assertSame(primary, assertThrows(RuntimeException.class, () -> NativeCalibrationStageHooks.nativeCustom(new Object(), new Object(), new Object(), true,
                    () -> { calls.incrementAndGet(); throw primary; })));
            assertEquals(1, calls.get()); assertArrayEquals(new Throwable[] {post}, primary.getSuppressed());
        }
    }
    @Test void actualResultCallbackFailurePreservesFollowingControlFailure() {
        RuntimeException primary = new IllegalArgumentException("callback"); Error post = new AssertionError("current"); AtomicInteger effects = new AtomicInteger();
        var listener = new Listener() {
            @Override public void afterResultCallback(CommandContext<?> context, Throwable failure) { assertSame(primary, failure); throw post; }
        };
        try (var scope = NativeCalibrationStageHooks.open(listener)) {
            assertSame(primary, assertThrows(RuntimeException.class, () -> NativeCalibrationStageHooks.nativeResultCallback((context, success, result) -> {
                effects.incrementAndGet(); assertFalse(success); assertEquals(0, result); throw primary;
            }, null, false, 0)));
            assertEquals(1, effects.get()); assertArrayEquals(new Throwable[] {post}, primary.getSuppressed());
        }
    }
    @Test void precheckFailurePreventsEffectAndNestedScopeCannotReplaceOwner() {
        AtomicInteger calls = new AtomicInteger(); ContractException denied = new ContractException("CANCELLATION_REQUESTED", "fixture");
        var listener = new Listener() { @Override public void beforeHandler(Object handler, CommandContext<?> context) { throw denied; } };
        try (var scope = NativeCalibrationStageHooks.open(listener)) {
            assertEquals("CALIBRATION_STAGE_REENTRANT", assertThrows(ContractException.class, () -> NativeCalibrationStageHooks.open(new Listener())).code());
            assertSame(denied, assertThrows(ContractException.class, () -> NativeCalibrationStageHooks.nativeHandler(context -> calls.incrementAndGet(), null)));
        }
        assertEquals(0, calls.get());
    }
    private static class Listener implements NativeCalibrationStageHooks.Listener {
        @Override public void beforeEntry(Object entry, Object source, Object context, Object frame) { }
        @Override public void beforeHandler(Object handler, CommandContext<?> context) { }
        @Override public void afterHandler(Object handler, CommandContext<?> context, Integer result, Throwable failure) { }
        @Override public void queueReturned(Object context, int quota, boolean overflow, int queued, int newTop) { }
        @Override public void beforeCustom(Object receiver, Object chain, Object frame, boolean modifier) { }
        @Override public void afterCustom(Object receiver, Object chain, Object frame, boolean modifier, Throwable failure) { }
        @Override public void frameReturned(Object frame, Integer result) { }
    }
}
