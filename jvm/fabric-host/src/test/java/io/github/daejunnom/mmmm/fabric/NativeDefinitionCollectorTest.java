package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import net.fabricmc.loader.api.ModContainer;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
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

    /** 기존 class port는 source metadata의 RuntimeException fallback을 지나지 않는다.
     * 실제 installation 메서드에 같은 종료 callback을 연결하며 게임/source 권한은 만들지 않는다. */
    private static ObjectNode installation(NativeSourceFacts.Checkpoint checkpoint, Runnable duringOrigin,
                                           AtomicInteger originCalls) throws ReflectiveOperationException {
        var constructor = NativeSourceFacts.class.getDeclaredConstructor(NativeSourceFacts.Checkpoint.class);
        constructor.setAccessible(true);
        NativeSourceFacts facts = constructor.newInstance(checkpoint);
        ModContainer container = (ModContainer) Proxy.newProxyInstance(ModContainer.class.getClassLoader(),
                new Class<?>[] { ModContainer.class }, (proxy, method, arguments) -> {
                    if (!"getOrigin".equals(method.getName())) throw new IllegalStateException("Unrequested metadata port");
                    originCalls.incrementAndGet(); duringOrigin.run(); return null;
                });
        var method = NativeSourceFacts.class.getDeclaredMethod("installation", ModContainer.class);
        method.setAccessible(true);
        return (ObjectNode) method.invoke(facts, container);
    }

    @Test void sourceMetadataPreservesOriginalStopBeforeAndAfterItsPortInsteadOfReturningUnknown() throws Exception {
        AtomicInteger untouched = new AtomicInteger();
        ContractException original = new ContractException("CANCELLATION_REQUESTED", "Original source request ended");
        assertSame(original, assertThrows(InvocationTargetException.class,
                () -> installation(() -> { throw original; }, () -> fail("Stopped source cannot read metadata"), untouched)).getCause());
        assertEquals(0, untouched.get());
        for (boolean cancel : new boolean[] { true, false }) {
            CompletableFuture<Object> response = new CompletableFuture<>(); AtomicInteger calls = new AtomicInteger();
            RuntimeException stopped = cancel ? original : new IllegalStateException("Original source response completed");
            NativeSourceFacts.Checkpoint checkpoint = () -> { if (response.isDone()) throw stopped; };
            assertSame(stopped, assertThrows(InvocationTargetException.class,
                    () -> installation(checkpoint, () -> {
                        if (cancel) response.cancel(false); else response.complete(new Object());
                    }, calls)).getCause());
            assertEquals(1, calls.get());
            assertTrue(response.isDone()); assertEquals(cancel, response.isCancelled());
        }
        assertEquals("unknown", installation(() -> { }, () -> { }, new AtomicInteger()).path("status").asText());
    }
    // 기존 raw port fixture를 실제 publication slot과 연결한다. 네이티브 관측을 발급하지 않는다.
    private static HostSession owner(NativeDefinitionSlot slot) {
        HostSession owner = new HostSession("fixture", "fixture", "fixture", "server", UUID.randomUUID(), Set.of(), false);
        owner.whenClosed(() -> slot.retire(owner)); return owner;
    }
    private static NativeDefinitionCollector.Snapshot completedRaw() {
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), () -> { }, new Port());
        collector.observe(NativeDefinitionCollectorTest.class, BLOCK); collector.finish(); return collector.snapshot();
    }
    @Test void retiredCollectorCannotPublishAfterClearOrDeleteANewerOwnersSnapshot() {
        NativeDefinitionSlot slot = new NativeDefinitionSlot(); Object server = new Object();
        HostSession oldOwner = owner(slot); HostSession newOwner = owner(slot);
        var observed = completedRaw();
        var old = slot.begin(oldOwner, server, "context", "digest", "epoch", 1);
        slot.retireAll(); assertFalse(slot.publish(old, observed)); assertEquals(0, slot.retainedBytes());
        var superseded = slot.begin(newOwner, server, "context", "digest", "epoch", 2);
        var fresh = slot.begin(newOwner, server, "context", "digest", "epoch", 2);
        assertTrue(slot.publish(fresh, observed));
        assertFalse(slot.publish(superseded, observed)); slot.retire(superseded);
        slot.retire(old); oldOwner.close(); assertFalse(slot.publish(old, observed));
        assertTrue(slot.hasRawObservation(newOwner, server, "context", "digest", "epoch", 2));
        assertFalse(slot.hasRawObservation(oldOwner, server, "context", "digest", "epoch", 1));
        assertEquals(observed.retainedBytes(), slot.retainedBytes()); newOwner.close(); assertEquals(0, slot.retainedBytes());
    }
    @Test void independentSessionCloseReleasesAnAlreadyPublishedRawSnapshot() {
        NativeDefinitionSlot slot = new NativeDefinitionSlot(); Object server = new Object(); HostSession owner = owner(slot);
        var ticket = slot.begin(owner, server, "context", "digest", "epoch", 1);
        assertTrue(slot.publish(ticket, completedRaw())); assertEquals(3, slot.retainedBytes());
        owner.close(); owner.close(); assertEquals(0, slot.retainedBytes());
        assertFalse(slot.publish(ticket, completedRaw()));
        assertFalse(slot.hasRawObservation(owner, server, "context", "digest", "epoch", 1));
        assertThrows(ContractException.class, () -> slot.begin(owner, server, "context", "digest", "epoch", 1));
    }
    @Test void failedPendingCollectorsFinallyCannotResurrectItsRetiredRawCandidate() {
        NativeDefinitionSlot slot = new NativeDefinitionSlot(); Object server = new Object(); HostSession owner = owner(slot);
        var ticket = slot.begin(owner, server, "context", "digest", "epoch", 1);
        NativeDefinitionCollector collector = new NativeDefinitionCollector(new NativeDefinitionCollector.Limits(2, 8), owner::checkOpen, new Port());
        collector.observe(getClass(), BLOCK); owner.close();
        ContractException failure = assertThrows(ContractException.class, collector::finish);
        collector.stopped(failure); var failed = collector.snapshot();
        assertEquals("SESSION_EXPIRED", failed.stopReason()); assertFalse(failed.completed()); assertTrue(failed.hasRawObservation());
        assertFalse(slot.publish(ticket, failed)); assertEquals(0, slot.retainedBytes());
    }
    @Test void concurrentCloseAndPublicationAlwaysRetireTheSameOwnersRaw() throws Exception {
        var observed = completedRaw();
        for (int attempt = 0; attempt < 16; attempt++) {
            NativeDefinitionSlot slot = new NativeDefinitionSlot(); Object server = new Object(); HostSession owner = owner(slot);
            var ticket = slot.begin(owner, server, "context", "digest", "epoch", 1);
            CompletableFuture<Void> start = new CompletableFuture<>();
            var publish = start.thenRunAsync(() -> slot.publish(ticket, observed));
            var close = start.thenRunAsync(owner::close);
            start.complete(null); CompletableFuture.allOf(publish, close).get(5, TimeUnit.SECONDS);
            assertTrue(owner.closed()); assertEquals(0, slot.retainedBytes());
            assertFalse(slot.hasRawObservation(owner, server, "context", "digest", "epoch", 1));
        }
    }
}
