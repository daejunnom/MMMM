package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 실제 JNI 증거를 발급하지 않는 순수 port fixture다. 기존 parser fixture에는 원자료 수집 수명/상한 검사가 없다. */
final class NativeDefinitionCollectorTest {
    private static final NativeRegistry.ClassRole BLOCK = NativeRegistry.ClassRole.BLOCK;
    private static NativeDefinitionCollector.RawObservation raw(Class<?> actualClass, int size) {
        return new NativeDefinitionCollector.RawObservation(actualClass,
                new NativeDefinitionCollector.Stamp(7, 11, 1, 13, 17, false), new byte[size], new byte[0]);
    }
    private static class Port implements NativeDefinitionCollector.ObservationPort {
        private int calls;
        private boolean current = true;
        @Override public NativeDefinitionCollector.RawObservation observe(Class<?> actualClass) { calls++; return raw(actualClass, 3); }
        @Override public boolean current(NativeDefinitionCollector.RawObservation original) { return current; }
    }
    @Test void actualClassIdentityIsDeduplicatedWhileRolesAndRawBytesRemainPrivate() {
        Port port = new Port();
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), () -> { }, port);
        collector.observe(getClass(), BLOCK); collector.observe(getClass(), NativeRegistry.ClassRole.PROPERTY_VALUE);
        collector.finish(); var snapshot = collector.snapshot();
        assertEquals(1, port.calls); assertEquals(1, snapshot.observations().size()); assertEquals(3, snapshot.retainedBytes());
        assertSame(getClass(), snapshot.observations().getFirst().actualClass());
        assertEquals(Set.of(BLOCK, NativeRegistry.ClassRole.PROPERTY_VALUE), snapshot.observations().getFirst().roles());
        assertTrue(snapshot.completed()); assertTrue(snapshot.hasRawObservation());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.observations().clear());
        assertEquals("OBSERVATION_CLOSED", assertThrows(ContractException.class, collector::checkpoint).code());
    }
    @Test void classAndByteOverflowRemainVisibleWithoutExceedingTheirBounds() {
        Port port = new Port();
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 4), () -> { }, port);
        collector.observe(getClass(), BLOCK); collector.observe(String.class, BLOCK); collector.observe(Integer.class, BLOCK);
        collector.finish(); var snapshot = collector.snapshot();
        assertEquals(2, port.calls); assertEquals(2, snapshot.observations().size()); assertEquals(1, snapshot.omittedInputs());
        assertEquals("OBSERVATION_CLASS_LIMIT", snapshot.overflowReason());
        assertEquals(3, snapshot.retainedBytes()); assertEquals("OBSERVATION_BYTE_LIMIT", snapshot.observations().get(1).reasonCode());
        assertNull(snapshot.observations().get(1).raw());
    }
    @Test void emptyAndAbsentBridgeAreDistinctFromObservedDefinitions() {
        Port port = new Port() {
            @Override public NativeDefinitionCollector.RawObservation observe(Class<?> actualClass) {
                if (actualClass == String.class) throw new NoClassDefFoundError("fixture-only absent bridge");
                return null;
            }
        };
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), () -> { }, port);
        collector.observe(getClass(), BLOCK); collector.observe(String.class, BLOCK); collector.finish();
        var snapshot = collector.snapshot(); assertFalse(snapshot.hasRawObservation());
        assertEquals("DEFINITION_NOT_OBSERVED", snapshot.observations().getFirst().reasonCode());
        assertEquals("OBSERVER_BRIDGE_UNAVAILABLE", snapshot.observations().get(1).reasonCode());
        assertEquals(NoClassDefFoundError.class.getName(), snapshot.observations().get(1).failureClass());
    }
    @Test void observationForAnotherActualClassCannotReplaceTheSelectedRegistryClass() {
        Port port = new Port() {
            @Override public NativeDefinitionCollector.RawObservation observe(Class<?> actualClass) { return raw(String.class, 3); }
        };
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), () -> { }, port);
        collector.observe(getClass(), BLOCK); collector.finish();
        assertEquals("OBSERVATION_IDENTITY_MISMATCH", collector.snapshot().observations().getFirst().reasonCode());
        assertFalse(collector.snapshot().hasRawObservation()); assertEquals(0, collector.snapshot().retainedBytes());
    }
    @Test void nativeProducerFailureStatusIsPreservedInsteadOfBecomingAnEmptyObservation() {
        Port port = new Port() {
            @Override public NativeDefinitionCollector.RawObservation observe(Class<?> actualClass) {
                throw new NativeDefinitionCollector.ProducerStateFailure(-7);
            }
        };
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), () -> { }, port);
        collector.observe(getClass(), BLOCK); collector.finish();
        var observed = collector.snapshot().observations().getFirst();
        assertEquals("OBSERVER_NATIVE_UNAVAILABLE", observed.reasonCode()); assertEquals(-7, observed.nativeStatus().intValue());
        assertFalse(collector.snapshot().hasRawObservation());
    }
    @Test void changedObservationAndExactSourceFailureCannotRemainCurrentRawData() {
        Port port = new Port();
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), () -> { }, port);
        collector.observe(getClass(), BLOCK); port.current = false; collector.finish();
        assertEquals(0, collector.snapshot().retainedBytes());
        assertEquals("OBSERVATION_CHANGED", collector.snapshot().observations().getFirst().reasonCode());
        Port failed = new Port() {
            @Override public boolean current(NativeDefinitionCollector.RawObservation original) {
                throw new ContractException("EXACT_SOURCE_REVOKED", "fixture-only source revocation");
            }
        };
        NativeDefinitionCollector revoked = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), () -> { }, failed);
        revoked.observe(getClass(), BLOCK); revoked.finish();
        assertEquals("EXACT_SOURCE_REVOKED", revoked.snapshot().observations().getFirst().reasonCode());
        assertFalse(revoked.snapshot().hasRawObservation());
    }
    @Test void actualSessionRevocationDuringObservationStopsTheOriginalCollection() {
        HostSession session = new HostSession("fixture", "fixture", "fixture", "server", UUID.randomUUID(), Set.of(), false);
        Port port = new Port() {
            @Override public NativeDefinitionCollector.RawObservation observe(Class<?> actualClass) { session.close(); return raw(actualClass, 3); }
        };
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), session::checkOpen, port);
        assertEquals("SESSION_EXPIRED", assertThrows(ContractException.class, () -> collector.observe(getClass(), BLOCK)).code());
        assertEquals("SESSION_EXPIRED", collector.snapshot().stopReason()); assertFalse(collector.snapshot().completed());
        assertEquals(0, collector.snapshot().retainedBytes());
    }
    @Test void originalControlFailureIsPreservedAfterPortWork() {
        AtomicInteger checks = new AtomicInteger(); ContractException original = new ContractException("DEADLINE_EXCEEDED", "fixture-only original deadline");
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8),
                () -> { if (checks.incrementAndGet() == 2) throw original; }, new Port());
        assertSame(original, assertThrows(ContractException.class, () -> collector.observe(getClass(), BLOCK)));
        assertEquals("DEADLINE_EXCEEDED", collector.snapshot().stopReason()); assertFalse(collector.snapshot().completed());
    }
}
