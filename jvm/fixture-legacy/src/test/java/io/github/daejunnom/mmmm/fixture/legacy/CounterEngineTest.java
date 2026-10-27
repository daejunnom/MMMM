package io.github.daejunnom.mmmm.fixture.legacy;

import org.junit.jupiter.api.Test;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** New fixture state has no original package example. These pure checks are not actual game or adapter acceptance. */
final class CounterEngineTest {
    private static final String EXECUTOR = "player-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private static final String DIMENSION = "minecraft:overworld";

    @Test void publicReadAndWriteShareOneCounterAndRejectCompareConflict() {
        CounterEngine engine = engine();
        assertEquals(0, engine.read(EXECUTOR, DIMENSION));
        assertEquals(37, engine.set(EXECUTOR, DIMENSION, 0, 37, "none"));
        assertEquals(37, engine.read(EXECUTOR, DIMENSION));
        assertCode("COUNTER_CONFLICT", () -> engine.set(EXECUTOR, DIMENSION, 0, 55, "none"));
        assertEquals(37, engine.read(EXECUTOR, DIMENSION));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("revision"));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void sameValueWriteDoesNotInventAnEffectOrRevision() {
        CounterEngine engine = engine();
        assertEquals(0, engine.set(EXECUTOR, DIMENSION, 0, 0, "none"));
        assertEquals(0L, engine.snapshot(EXECUTOR, DIMENSION).get("revision"));
        assertEquals(0L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void snapshotIsClosedAndImmutable() {
        Map<String, Object> result = engine().snapshot(EXECUTOR, DIMENSION);
        assertEquals(java.util.Set.of("format", "value", "revision", "mutationCount", "session", "tick", "executorHandle", "dimension"), result.keySet());
        assertThrows(UnsupportedOperationException.class, () -> result.put("value", 999));
    }

    @Test void beforeMutationFaultPreservesOriginalValueAndRevision() {
        CounterEngine engine = engine();
        assertCode("COUNTER_BEFORE_MUTATION", () -> engine.set(EXECUTOR, DIMENSION, 0, 55, "before_mutation"));
        assertCode("COUNTER_BEFORE_MUTATION", () -> engine.beginJob(EXECUTOR, DIMENSION, 0, 55, 3, "before_mutation"));
        assertEquals(0, engine.read(EXECUTOR, DIMENSION));
        assertEquals(0L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void lostResponseHasOneActualMutationAndIndependentReadback() {
        CounterEngine engine = engine();
        assertCode("COUNTER_RESPONSE_LOST", () -> engine.set(EXECUTOR, DIMENSION, 0, 71, "lost_response"));
        assertEquals(71, engine.read(EXECUTOR, DIMENSION));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
        assertCode("COUNTER_CONFLICT", () -> engine.set(EXECUTOR, DIMENSION, 0, 71, "none"));
    }

    @Test void jobMutatesSynchronouslyAndTicksOnlyDeliverCompletion() {
        CounterEngine engine = engine();
        CounterEngine.Job job = engine.beginJob(EXECUTOR, DIMENSION, 0, 19, 2, "none");
        assertEquals(19, engine.read(EXECUTOR, DIMENSION));
        assertFalse(job.stage().toCompletableFuture().isDone());
        assertEquals(0, snapshot(job, "before").get("value"));
        assertEquals(19, snapshot(job, "after").get("value"));
        engine.tick(); assertFalse(job.stage().toCompletableFuture().isDone());
        engine.tick(); assertEquals(Map.of("value", 19), job.stage().toCompletableFuture().join());
        assertEquals("complete", job.observation().get("status"));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void cooperativeCancelStopsDeliveryAndPreservesEarlierMutation() {
        CounterEngine engine = engine();
        CounterEngine.Job job = engine.beginJob(EXECUTOR, DIMENSION, 0, 23, 4, "none");
        assertTrue(engine.cancel(job, EXECUTOR, DIMENSION));
        assertStageCode("COUNTER_JOB_CANCELLED", job);
        assertEquals("cancelled", job.observation().get("status"));
        assertEquals(true, job.observation().get("stopConfirmed"));
        for (int index = 0; index < 5; index++) engine.tick();
        assertEquals(23, engine.read(EXECUTOR, DIMENSION));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void lateCompletionDoesNotCreateAPostCancelMutation() {
        CounterEngine engine = engine();
        CounterEngine.Job job = engine.beginJob(EXECUTOR, DIMENSION, 0, 29, 3, "late_completion");
        assertFalse(engine.cancel(job, EXECUTOR, DIMENSION));
        assertEquals(false, job.observation().get("stopConfirmed"));
        assertEquals(true, job.observation().get("cancellationRequested"));
        engine.tick(); engine.tick(); assertFalse(job.stage().toCompletableFuture().isDone());
        engine.tick(); assertEquals(Map.of("value", 29), job.stage().toCompletableFuture().join());
        assertEquals("complete", job.observation().get("status"));
        assertEquals(29, engine.read(EXECUTOR, DIMENSION));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void synchronousCompletionCallbackCannotRewriteAnAlreadyCancelledDueTicket() {
        CounterEngine engine = engine();
        CounterEngine.Job first = engine.beginJob(EXECUTOR, DIMENSION, 0, 27, 1, "none");
        CounterEngine.Job second = engine.beginJob(EXECUTOR, DIMENSION, 27, 28, 1, "none");
        first.stage().whenComplete((result, failure) -> engine.cancel(second, EXECUTOR, DIMENSION));
        engine.tick();
        assertEquals("complete", first.observation().get("status"));
        assertEquals("cancelled", second.observation().get("status"));
        assertStageCode("COUNTER_JOB_CANCELLED", second);
        assertEquals(28, engine.read(EXECUTOR, DIMENSION));
        assertEquals(2L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void failedJobResponseRetainsBeforeAndAfterFacts() {
        CounterEngine engine = engine();
        CounterEngine.Job job = engine.beginJob(EXECUTOR, DIMENSION, 0, 31, 1, "lost_response");
        engine.tick();
        CompletionException failure = assertThrows(CompletionException.class, () -> job.stage().toCompletableFuture().join());
        assertEquals("COUNTER_RESPONSE_LOST", ((LegacyCounterException) failure.getCause()).code());
        assertEquals("failed", job.observation().get("status"));
        assertEquals(0, snapshot(job, "before").get("value"));
        assertEquals(31, snapshot(job, "after").get("value"));
        assertEquals(31, engine.read(EXECUTOR, DIMENSION));
    }

    @Test void completionRechecksConnectedContextWithoutRepeatingWrite() {
        AtomicBoolean connected = new AtomicBoolean(true);
        CounterEngine engine = new CounterEngine("fixture-live", (executor, dimension, write) -> {
            if (!connected.get()) throw new LegacyCounterException("EXECUTOR_DISCONNECTED", "Disconnected fixture player");
        });
        CounterEngine.Job job = engine.beginJob(EXECUTOR, DIMENSION, 0, 43, 1, "none");
        connected.set(false); engine.tick();
        assertEquals("EXECUTOR_DISCONNECTED", job.observation().get("errorCode"));
        connected.set(true);
        assertEquals(43, engine.read(EXECUTOR, DIMENSION));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void permissionRevocationPreventsCancelAndNewWriteWithoutErasingExistingFacts() {
        AtomicBoolean writes = new AtomicBoolean(true);
        CounterEngine engine = new CounterEngine("fixture-permission", (executor, dimension, write) -> {
            if (write && !writes.get()) throw new LegacyCounterException("PERMISSION_DENIED", "Revoked fixture administrator");
        });
        CounterEngine.Job job = engine.beginJob(EXECUTOR, DIMENSION, 0, 47, 2, "none");
        writes.set(false);
        assertCode("PERMISSION_DENIED", () -> engine.cancel(job, EXECUTOR, DIMENSION));
        assertCode("PERMISSION_DENIED", () -> engine.set(EXECUTOR, DIMENSION, 47, 49, "none"));
        assertEquals(47, engine.read(EXECUTOR, DIMENSION));
        engine.tick(); engine.tick();
        assertEquals("complete", job.observation().get("status"));
        assertEquals(1L, engine.snapshot(EXECUTOR, DIMENSION).get("mutationCount"));
    }

    @Test void actualTicketsCannotCancelAnotherTargetOrServerSession() {
        CounterEngine original = engine();
        CounterEngine.Job job = original.beginJob(EXECUTOR, DIMENSION, 0, 53, 2, "none");
        assertCode("COUNTER_JOB_SCOPE", () -> original.cancel(job, "player-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", DIMENSION));
        assertCode("COUNTER_JOB_SCOPE", () -> engine().cancel(job, EXECUTOR, DIMENSION));
        assertFalse(job.stage().toCompletableFuture().isDone());
    }

    @Test void serverStopSettlesPendingDeliveryAndNewSessionStartsAtZero() {
        CounterEngine original = engine();
        CounterEngine.Job job = original.beginJob(EXECUTOR, DIMENSION, 0, 59, 2, "late_completion");
        original.stop();
        assertEquals("cancelled", job.observation().get("status"));
        assertEquals("SESSION_ENDED", job.observation().get("errorCode"));
        assertStageCode("SESSION_ENDED", job);
        assertEquals(59, snapshot(job, "after").get("value"));
        assertCode("SESSION_ENDED", () -> original.read(EXECUTOR, DIMENSION));
        assertCode("SESSION_ENDED", original::tick);
        assertEquals(0, engine().read(EXECUTOR, DIMENSION));
    }

    @Test void cellBoundCannotBeConsumedByReadsAndCannotBeSilentlyExceededByWrites() {
        CounterEngine engine = engine();
        for (int index = 1; index <= 64; index++) engine.set("player-" + new UUID(0, index), DIMENSION, 0, index, "none");
        assertEquals(0, engine.read(EXECUTOR, DIMENSION));
        assertCode("COUNTER_CELL_LIMIT", () -> engine.set(EXECUTOR, DIMENSION, 0, 1, "none"));
        assertEquals(0, engine.read(EXECUTOR, DIMENSION));
    }

    @Test void jobBoundRejectsBeforeMutationAndReleasesAfterCompletion() {
        CounterEngine engine = engine();
        for (int index = 0; index < 16; index++) engine.beginJob(EXECUTOR, DIMENSION, index, index + 1, 200, "none");
        assertCode("COUNTER_JOB_LIMIT", () -> engine.beginJob(EXECUTOR, DIMENSION, 16, 17, 1, "none"));
        assertEquals(16, engine.read(EXECUTOR, DIMENSION));
        for (int index = 0; index < 200; index++) engine.tick();
        CounterEngine.Job next = engine.beginJob(EXECUTOR, DIMENSION, 16, 61, 0, "none");
        assertEquals("complete", next.observation().get("status"));
        assertEquals(61, engine.read(EXECUTOR, DIMENSION));
    }

    @Test void counterDelayScopeAndFaultArgumentsAreClosedAndBounded() {
        CounterEngine engine = engine();
        assertCode("INVALID_ARGUMENT", () -> engine.set(EXECUTOR, DIMENSION, 0, 10_001, "none"));
        assertCode("INVALID_ARGUMENT", () -> engine.set(EXECUTOR, DIMENSION, -1, 1, "none"));
        assertCode("INVALID_ARGUMENT", () -> engine.beginJob(EXECUTOR, DIMENSION, 0, 1, 201, "none"));
        assertCode("INVALID_ARGUMENT", () -> engine.beginJob(EXECUTOR, DIMENSION, 0, 1, -1, "none"));
        assertCode("INVALID_ARGUMENT", () -> engine.set(EXECUTOR, DIMENSION, 0, 1, "late_completion"));
        assertCode("INVALID_ARGUMENT", () -> engine.set(EXECUTOR, DIMENSION, 0, 1, "unknown"));
        assertCode("INVALID_ARGUMENT", () -> engine.set(EXECUTOR, DIMENSION, 0, 1, "x".repeat(33)));
        assertCode("INVALID_ARGUMENT", () -> engine.read("player-AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", DIMENSION));
        assertCode("INVALID_ARGUMENT", () -> engine.read(EXECUTOR, "Minecraft:overworld"));
        assertEquals(0, engine.read(EXECUTOR, DIMENSION));
    }

    @Test void returnedStageCannotCompleteTheOwnedEngineFuture() {
        CounterEngine engine = engine();
        CounterEngine.Job job = engine.beginJob(EXECUTOR, DIMENSION, 0, 67, 1, "none");
        job.stage().toCompletableFuture().complete(Map.of("status", "forged"));
        assertFalse(job.stage().toCompletableFuture().isDone());
        engine.tick();
        assertEquals(Map.of("value", 67), job.stage().toCompletableFuture().join());
        assertEquals("complete", job.observation().get("status"));
        assertThrows(UnsupportedOperationException.class, () -> job.observation().put("stopConfirmed", false));
        assertThrows(UnsupportedOperationException.class, () -> snapshot(job, "after").put("value", 999));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> snapshot(CounterEngine.Job job, String name) { return (Map<String, Object>) job.observation().get(name); }
    private static CounterEngine engine() { return new CounterEngine("fixture-test", (executor, dimension, write) -> { }); }
    private static void assertStageCode(String code, CounterEngine.Job job) {
        CompletionException failure = assertThrows(CompletionException.class, () -> job.stage().toCompletableFuture().join());
        assertEquals(code, ((LegacyCounterException) failure.getCause()).code());
    }
    private static void assertCode(String code, org.junit.jupiter.api.function.Executable action) {
        assertEquals(code, assertThrows(LegacyCounterException.class, action).code());
    }
}
