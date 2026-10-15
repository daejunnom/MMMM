package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.sdk.ContractException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 기존 raw collector port fixture로는 실제 virtual/상속/hidden SAM의 reflection 경로를
 * 확인할 수 없어 작은 receiver만 둔다. 이 검사는 실제 JNI view나 승인 발급의 양성이 아니다.
 */
final class NativeCalibrationExecutablesTest {
    public interface Operation { int apply(int value); }
    public static class Parent implements Operation {
        static int invocations;
        @Override public int apply(int value) { invocations++; return value; }
        public int inherited(int[] input, String[][] names) { invocations++; return input.length + names.length; }
        public static int staticCall(int value) { invocations++; return value; }
        public native int nativeCall(int value);
        private int privateCall(int value) { invocations++; return value; }
    }
    public static final class Child extends Parent {
        @Override public int apply(int value) { invocations++; return value + 1; }
    }
    public interface GenericOperation { Object value(); }
    public static final class Covariant implements GenericOperation {
        @Override public String value() { Parent.invocations++; return "value"; }
    }
    private static NativeCalibrationExecutables.Selection selection(Object receiver, Method method) {
        return new NativeCalibrationExecutables.Selection(receiver, method, NativeCalibrationExecutables.Role.HANDLER);
    }

    @Test void actualVirtualOverrideAndInheritedDescriptorAreResolvedWithoutInvokingReceiver() throws Exception {
        Parent.invocations = 0; Child child = new Child();
        Method actual = NativeCalibrationExecutables.resolveVirtual(selection(child, Operation.class.getMethod("apply", int.class)), false);
        assertEquals(Child.class.getMethod("apply", int.class), actual);
        Method inherited = NativeCalibrationExecutables.resolveVirtual(selection(child, Parent.class.getMethod("inherited", int[].class, String[][].class)), false);
        assertEquals(Parent.class, inherited.getDeclaringClass());
        assertEquals("([I[[Ljava/lang/String;)I", NativeCalibrationExecutables.descriptor(inherited));
        Method bridge = NativeCalibrationExecutables.resolveVirtual(selection(new Covariant(), GenericOperation.class.getMethod("value")), false);
        assertTrue(bridge.isBridge()); assertTrue(bridge.isSynthetic());
        assertEquals("()Ljava/lang/Object;", NativeCalibrationExecutables.descriptor(bridge));
        assertEquals(0, Parent.invocations);
    }

    @Test void unrelatedStaticPrivateAndNativeMethodsAreNotInvokedOrSubstituted() throws Exception {
        assertReason(NativeCalibrationExecutables.Reason.RECEIVER_METHOD_MISMATCH,
                selection(new Object(), Operation.class.getMethod("apply", int.class)));
        assertReason(NativeCalibrationExecutables.Reason.NON_PUBLIC_VIRTUAL_METHOD,
                selection(new Parent(), Parent.class.getMethod("staticCall", int.class)));
        assertReason(NativeCalibrationExecutables.Reason.NON_PUBLIC_VIRTUAL_METHOD,
                selection(new Parent(), Parent.class.getDeclaredMethod("privateCall", int.class)));
        assertReason(NativeCalibrationExecutables.Reason.NON_EXECUTABLE_METHOD,
                selection(new Parent(), Parent.class.getMethod("nativeCall", int.class)));
    }

    @Test void hiddenSamReflectionIsOnlySelectionMetadataAndDoesNotExecuteItsStaticTarget() throws Exception {
        Parent.invocations = 0;
        Runnable receiver = () -> Parent.invocations++;
        assertTrue(receiver.getClass().isHidden());
        Method actual = NativeCalibrationExecutables.resolveVirtual(selection(receiver, Runnable.class.getMethod("run")), true);
        assertSame(receiver.getClass(), actual.getDeclaringClass());
        assertEquals("()V", NativeCalibrationExecutables.descriptor(actual));
        assertEquals(0, Parent.invocations);
        // acquire() still requires the real native recipe, Class identity and target record.
        // The reflection result above has no factory that can manufacture that witness.
    }

    @Test void originalMethodFailureRemainsPrimaryWhenTheSameControlStopsAfterIt() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        ContractException stopped = new ContractException("CANCELLATION_REQUESTED", "Original fixture control stopped");
        var selected = selection(new Parent(), Parent.class.getMethod("staticCall", int.class));
        var failure = assertThrows(NativeCalibrationExecutables.Failure.class, () ->
                NativeCalibrationExecutables.acquire(Collections.singletonList(selected), () -> {
                    if (checks.incrementAndGet() == 3) throw stopped;
                }));
        assertEquals(NativeCalibrationExecutables.Status.UNSUPPORTED, failure.status());
        assertEquals(NativeCalibrationExecutables.Reason.NON_PUBLIC_VIRTUAL_METHOD, failure.reason());
        assertArrayEquals(new Throwable[] { stopped }, failure.getSuppressed());
    }

    @Test void selectionBoundsAndOriginalCancellationFailBeforeAnyNativeAcquisition() throws Exception {
        var selected = selection(new Parent(), Operation.class.getMethod("apply", int.class));
        var limit = assertThrows(NativeCalibrationExecutables.Failure.class, () ->
                NativeCalibrationExecutables.acquire(Collections.nCopies(NativeCalibrationExecutables.MAX_SELECTIONS + 1, selected), () -> { }));
        assertEquals(NativeCalibrationExecutables.Status.LIMIT, limit.status());
        assertEquals(NativeCalibrationExecutables.Reason.SELECTION_LIMIT, limit.reason());
        ContractException stopped = new ContractException("CANCELLATION_REQUESTED", "Original fixture control stopped");
        assertSame(stopped, assertThrows(ContractException.class, () ->
                NativeCalibrationExecutables.acquire(Collections.singletonList(selected), () -> { throw stopped; })));
    }

    private static void assertReason(NativeCalibrationExecutables.Reason expected, NativeCalibrationExecutables.Selection selected) {
        var failure = assertThrows(NativeCalibrationExecutables.Failure.class, () -> NativeCalibrationExecutables.resolveVirtual(selected, false));
        assertEquals(NativeCalibrationExecutables.Status.UNSUPPORTED, failure.status());
        assertEquals(expected, failure.reason());
    }
}
