package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 원본 예시는 복구 claim과 실제 future·대기 작업의 차이를 다루지 않는다. 대상은 메모리 fixture이며 게임 복원 인수 증거가 아니다. */
final class UndoJobBoundaryTest {
    private static final Instant NOW = Instant.parse("2026-10-13T11:59:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final UUID PLAYER = UUID.fromString("794f275c-03cd-4f07-b913-f2e4afef988f");
    private static final String UNDO = "fixture:undo_text";
    private static final String PRIVATE_MARKER = "PRIVATE_PROVIDER_UNDO_MATERIAL";
    private static final Set<String> REFERENCES = Set.of("tokenRecordId", "tokenRecordDigest",
            "sourceOperationId", "sourceStepId", "sourceInvocationId");
    private static final Set<String> JOB_FIELDS = Set.of("format", "invocation", "invocationDigest",
            "sourceInvocation", "sourceReceipt", "callbackEntered", "mutationStarted", "cancellationRequested",
            "polling", "rawCallbackSettled", "rawCallbackFailed", "contextClosed", "pendingGameThreadTasks",
            "providerJobOutstanding", "executorState");
    private final ContractJson contracts = new ContractJson();

    @Test void synchronousFixtureRestoreKeepsExactClosedSourceAssociationAfterOriginalSessionCloses() throws IOException {
        AtomicInteger callbacks = new AtomicInteger();
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> {
            callbacks.incrementAndGet(); local.requireGameThread();
            assertEquals(REFERENCES, fields(invocation.arguments()));
            assertFalse(invocation.arguments().has("text"));
            assertEquals(PRIVATE_MARKER, token.path("privateMarker").asText());
            local.beginMutation();
            String before = target.value.getAndSet(token.path("before").asText());
            local.recordEffect(ContractJson.newObject().put("kind", "fixture_memory_restore")
                    .put("before", before).put("after", target.value.get()));
            return CompletableFuture.completedFuture(complete("provider reported fixture restore", "recorded"));
        }, null)) {
            test.startSource();
            ObjectNode sourceWire = test.source.wire(); ObjectNode receipt = test.receipt.deepCopy();
            ObjectNode current = test.source.context().put("policyRevision", "0".repeat(64));
            current.put("contextDigest", ContractJson.contextDigest(current));
            HostSession approved = installed(current);
            test.runtime.closeSession(test.sourceSession);
            Invocation recovery = test.recovery("recover-1", current);
            var result = test.runtime.dispatch(approved, recovery); test.queue.runNext();
            assertEquals("complete", result.toCompletableFuture().join().status());
            assertEquals("before", test.target.value.get()); assertEquals(1, callbacks.get());
            assertTrue(test.target.preconditionChecks.get() >= 4);
            ObjectNode job = test.runtime.undoJob(approved, current, recovery.invocationId());
            assertEquals(JOB_FIELDS, fields(job)); assertEquals("mmmm.host.undo-job/1", job.path("format").asText());
            assertEquals(recovery.wire(), job.path("invocation"));
            assertEquals(ContractJson.digest(recovery.wire()), job.path("invocationDigest").asText());
            assertEquals(sourceWire, job.path("sourceInvocation")); assertEquals(receipt, job.path("sourceReceipt"));
            assertTrue(job.path("callbackEntered").asBoolean()); assertTrue(job.path("mutationStarted").asBoolean());
            assertTrue(job.path("rawCallbackSettled").asBoolean()); assertFalse(job.path("rawCallbackFailed").asBoolean());
            assertTrue(job.path("contextClosed").asBoolean()); assertEquals(0, job.path("pendingGameThreadTasks").asInt());
            assertFalse(job.path("providerJobOutstanding").asBoolean());
            assertFalse(job.path("cancellationRequested").asBoolean()); assertFalse(job.path("polling").asBoolean());
            assertEquals("synchronous_quiescent", job.path("executorState").asText());
            assertFalse(job.toString().contains(PRIVATE_MARKER));
            job.withObject("sourceInvocation").withObject("arguments").put("text", "changed returned source");
            job.withObject("sourceReceipt").put("sourceStepId", "changed-returned-receipt");
            ObjectNode second = test.runtime.undoJob(approved, current, recovery.invocationId());
            assertEquals(sourceWire, second.path("sourceInvocation")); assertEquals(receipt, second.path("sourceReceipt"));
            assertCode("INVOCATION_UNKNOWN", () -> test.runtime.undoJob(installed(current), current, recovery.invocationId()));
            assertCode("STALE_CONTEXT", () -> test.runtime.undoJob(approved, test.source.context(), recovery.invocationId()));
        }
    }

    @Test void pendingRawFutureHasNoCompletionFactAndSourceAssociationDoesNotDependOnProviderOutput() throws IOException {
        CompletableFuture<ProviderResult> raw = new CompletableFuture<>();
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> raw, null)) {
            test.startSource(); Invocation recovery = test.recovery("recover-1", test.source.context());
            var result = test.runtime.dispatch(test.sourceSession, recovery);
            ObjectNode queued = test.job(recovery);
            assertEquals("not_entered", queued.path("executorState").asText());
            assertFalse(queued.path("callbackEntered").asBoolean()); assertTrue(queued.path("sourceReceipt").isNull());
            test.queue.runNext();
            ObjectNode pending = test.job(recovery);
            assertTrue(pending.path("callbackEntered").asBoolean()); assertFalse(pending.path("mutationStarted").asBoolean());
            assertFalse(pending.path("rawCallbackSettled").asBoolean()); assertFalse(pending.path("rawCallbackFailed").asBoolean());
            assertFalse(pending.path("contextClosed").asBoolean());
            assertEquals("running", pending.path("executorState").asText());
            assertEquals(test.source.wire(), pending.path("sourceInvocation"));
            assertEquals(test.receipt, pending.path("sourceReceipt")); assertFalse(result.toCompletableFuture().isDone());
            raw.complete(complete("provider completed without restoring fixture", "unknown"));
            assertEquals("complete", result.toCompletableFuture().join().status());
            assertEquals("synchronous_quiescent", test.job(recovery).path("executorState").asText());
            assertEquals("after", test.target.value.get());
        }
    }

    @Test void failedActualFutureKeepsSourceAssociationAndCannotReclaimThroughANewInvocation() throws IOException {
        AtomicInteger callbacks = new AtomicInteger();
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> {
            callbacks.incrementAndGet();
            return CompletableFuture.failedFuture(new ContractException("FIXTURE_RECOVER_FAILED", "Fixture callback failed"));
        }, null)) {
            test.startSource(); Invocation recovery = test.recovery("recover-1", test.source.context());
            var first = test.runtime.dispatch(test.sourceSession, recovery); test.queue.runNext();
            ProviderResult failed = first.toCompletableFuture().join();
            assertEquals("failed", failed.status());
            ObjectNode job = test.job(recovery);
            assertTrue(job.path("callbackEntered").asBoolean()); assertTrue(job.path("rawCallbackSettled").asBoolean());
            assertTrue(job.path("rawCallbackFailed").asBoolean()); assertEquals(test.receipt, job.path("sourceReceipt"));
            assertEquals(test.source.wire(), job.path("sourceInvocation"));
            assertEquals("after", test.target.value.get());
            assertEquals(failed.wire(), test.runtime.dispatch(test.sourceSession, recovery).toCompletableFuture().join().wire());
            assertEquals(1, callbacks.get()); assertEquals(0, test.queue.size());
            Invocation second = test.recovery("recover-2", test.source.context());
            var rejected = test.runtime.dispatch(test.sourceSession, second); test.queue.runNext();
            assertEquals("RECOVERY_EXPIRED", rejected.toCompletableFuture().join().wire().path("diagnostics").get(0).path("code").asText());
            assertFalse(test.job(second).path("callbackEntered").asBoolean());
            assertTrue(test.job(second).path("sourceReceipt").isNull()); assertEquals(1, callbacks.get());
        }
    }

    @Test void queuedGameThreadTaskKeepsExecutorUnknownUntilActualQueueDrainEvenAfterCompleteReport() throws IOException {
        AtomicReference<CompletionStage<Integer>> queued = new AtomicReference<>();
        AtomicInteger effects = new AtomicInteger();
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> {
            queued.set(local.onGameThread(() -> {
                effects.incrementAndGet(); local.beginMutation(); target.value.set(token.path("before").asText()); return 1;
            }));
            return CompletableFuture.completedFuture(complete("reported before queued work ran", "unknown"));
        }, null)) {
            test.startSource(); Invocation recovery = test.recovery("recover-1", test.source.context());
            var result = test.runtime.dispatch(test.sourceSession, recovery); test.queue.runNext();
            assertEquals("complete", result.toCompletableFuture().join().status());
            ObjectNode beforeDrain = test.job(recovery);
            assertTrue(beforeDrain.path("rawCallbackSettled").asBoolean()); assertTrue(beforeDrain.path("contextClosed").asBoolean());
            assertEquals(1, beforeDrain.path("pendingGameThreadTasks").asInt());
            assertEquals("unknown", beforeDrain.path("executorState").asText()); assertEquals(0, effects.get());
            test.queue.runNext();
            CompletionException failure = assertThrows(CompletionException.class, () -> queued.get().toCompletableFuture().join());
            assertEquals("INVOCATION_FINISHED", ((ContractException) failure.getCause()).code());
            assertEquals(0, test.job(recovery).path("pendingGameThreadTasks").asInt());
            assertEquals("synchronous_quiescent", test.job(recovery).path("executorState").asText());
            assertEquals(0, effects.get()); assertEquals("after", test.target.value.get());
        }
    }

    @Test void boundedTimeoutDoesNotSetRawFutureFactsAndLateActualCompletionDoesNotReplaceTheReport() throws Exception {
        CompletableFuture<ProviderResult> raw = new CompletableFuture<>();
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> raw, null)) {
            test.startSource();
            ObjectNode wire = test.recovery("recover-1", test.source.context()).wire();
            wire.put("deadlineAt", NOW.plusMillis(25).toString()); Invocation recovery = new Invocation(contracts, wire);
            var result = test.runtime.dispatch(test.sourceSession, recovery); test.queue.runNext();
            ProviderResult timedOut = result.toCompletableFuture().get(3, TimeUnit.SECONDS);
            assertEquals("failed", timedOut.status()); assertFalse(raw.isDone());
            ObjectNode bounded = test.job(recovery);
            assertTrue(bounded.path("contextClosed").asBoolean()); assertFalse(bounded.path("rawCallbackSettled").asBoolean());
            assertFalse(bounded.path("rawCallbackFailed").asBoolean()); assertEquals("unknown", bounded.path("executorState").asText());
            assertEquals(test.receipt, bounded.path("sourceReceipt"));
            raw.complete(complete("late provider report", "unknown"));
            ObjectNode late = test.job(recovery);
            assertTrue(late.path("rawCallbackSettled").asBoolean()); assertFalse(late.path("rawCallbackFailed").asBoolean());
            assertEquals(timedOut.wire(), test.runtime.operation(test.sourceSession, recovery.invocationId()).path("result"));
            assertEquals(timedOut.wire(), result.toCompletableFuture().join().wire());
            assertEquals(test.receipt, late.path("sourceReceipt")); assertEquals("after", test.target.value.get());
        }
    }

    @Test void queueCapacityRejectsTheThirtyThirdTaskWithoutLosingTheActualPendingCount() throws IOException {
        AtomicInteger queuedEffects = new AtomicInteger();
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> {
            for (int index = 0; index < 32; index++) local.onGameThread(queuedEffects::incrementAndGet);
            assertCode("HOST_QUEUE_LIMIT", () -> local.onGameThread(queuedEffects::incrementAndGet));
            return CompletableFuture.completedFuture(complete("reported with queued fixture work", "unknown"));
        }, null)) {
            test.startSource(); Invocation recovery = test.recovery("recover-1", test.source.context());
            var result = test.runtime.dispatch(test.sourceSession, recovery); test.queue.runNext();
            assertEquals("complete", result.toCompletableFuture().join().status());
            assertEquals(32, test.queue.size()); assertEquals(32, test.job(recovery).path("pendingGameThreadTasks").asInt());
            assertEquals("unknown", test.job(recovery).path("executorState").asText());
            for (int index = 0; index < 32; index++) test.queue.runNext();
            assertEquals(0, test.queue.size()); assertEquals(0, test.job(recovery).path("pendingGameThreadTasks").asInt());
            assertEquals("synchronous_quiescent", test.job(recovery).path("executorState").asText());
            assertEquals(0, queuedEffects.get()); assertEquals("after", test.target.value.get());
        }
    }

    @Test void rejectedClaimDoesNotEnterCallbackOrConsumeTheValidSourceToken() throws IOException {
        AtomicInteger calls = new AtomicInteger();
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> {
            calls.incrementAndGet(); return CompletableFuture.completedFuture(complete("callback entered", "unknown"));
        }, null)) {
            test.startSource();
            ObjectNode wire = test.recovery("recover-rejected", test.source.context()).wire();
            wire.withObject("arguments").put("sourceStepId", "different-source-step");
            wire.put("argumentsDigest", ContractJson.digest(wire.path("arguments")));
            Invocation rejected = new Invocation(contracts, wire);
            var result = test.runtime.dispatch(test.sourceSession, rejected); test.queue.runNext();
            assertEquals("failed", result.toCompletableFuture().join().status());
            ObjectNode job = test.job(rejected);
            assertFalse(job.path("callbackEntered").asBoolean()); assertFalse(job.path("mutationStarted").asBoolean());
            assertFalse(job.path("rawCallbackSettled").asBoolean()); assertFalse(job.path("rawCallbackFailed").asBoolean());
            assertTrue(job.path("sourceInvocation").isNull()); assertTrue(job.path("sourceReceipt").isNull());
            assertEquals(0, calls.get());
            Invocation valid = test.recovery("recover-valid", test.source.context());
            var successful = test.runtime.dispatch(test.sourceSession, valid); test.queue.runNext();
            assertEquals("complete", successful.toCompletableFuture().join().status());
            assertEquals(test.receipt, test.job(valid).path("sourceReceipt")); assertEquals(1, calls.get());
        }
    }

    @Test void immediateMutationPreconditionStopsFixtureDriftAfterTheRecoveryCallbackHasEntered() throws IOException {
        try (Scenario test = new Scenario("synchronous", (invocation, token, local, target) -> {
            target.value.set("interference"); local.beginMutation();
            target.value.set(token.path("before").asText());
            return CompletableFuture.completedFuture(complete("unexpected restore", "recorded"));
        }, null)) {
            test.startSource(); Invocation recovery = test.recovery("recover-1", test.source.context());
            var result = test.runtime.dispatch(test.sourceSession, recovery); test.queue.runNext();
            assertEquals("FIXTURE_TARGET_DRIFT", result.toCompletableFuture().join().wire().path("diagnostics").get(0).path("code").asText());
            assertTrue(test.job(recovery).path("callbackEntered").asBoolean());
            assertFalse(test.job(recovery).path("mutationStarted").asBoolean());
            assertEquals(test.receipt, test.job(recovery).path("sourceReceipt"));
            assertEquals("interference", test.target.value.get());
        }
    }

    @Test void providerJobAcceptanceAndTerminalPollStayDistinctFromOwnedExecutorQuiescence() throws IOException {
        try (Scenario test = new Scenario("job", (invocation, token, local, target) -> {
            String handle = local.createHandle("job", "fixture-job", String.class);
            ObjectNode value = complete("accepted", "unknown").wire().put("status", "job_accepted").put("jobHandle", handle);
            return CompletableFuture.completedFuture(new ProviderResult(contracts, value));
        }, (handle, local) -> CompletableFuture.completedFuture(complete("provider terminal poll", "unknown")))) {
            test.startSource(); Invocation recovery = test.recovery("recover-1", test.source.context());
            var result = test.runtime.dispatch(test.sourceSession, recovery); test.queue.runNext();
            assertEquals("job_accepted", result.toCompletableFuture().join().status());
            ObjectNode accepted = test.job(recovery);
            assertTrue(accepted.path("rawCallbackSettled").asBoolean()); assertTrue(accepted.path("providerJobOutstanding").asBoolean());
            assertFalse(accepted.path("contextClosed").asBoolean());
            var poll = test.runtime.poll(test.sourceSession, recovery.invocationId());
            assertTrue(test.job(recovery).path("polling").asBoolean()); test.queue.runNext();
            assertTrue(poll.toCompletableFuture().join().path("providerCompleted").asBoolean());
            ObjectNode terminal = test.job(recovery);
            assertTrue(terminal.path("providerJobOutstanding").asBoolean()); assertTrue(terminal.path("contextClosed").asBoolean());
            assertFalse(terminal.path("polling").asBoolean());
            assertEquals("unknown", terminal.path("executorState").asText()); assertEquals("after", test.target.value.get());
        }
    }

    private final class Scenario implements AutoCloseable {
        private final QueueThread queue = new QueueThread();
        private final FixtureTarget target = new FixtureTarget();
        private final ObjectNode sourceAction;
        private final ObjectNode undoAction;
        private final Invocation source;
        private final HostSession sourceSession;
        private final HostRuntime runtime;
        private ObjectNode receipt;

        private Scenario(String completion, RecoveryBody recovery, OptionalCallbacks.Poll poll) throws IOException {
            sourceAction = ContractJson.object(fixture("provider-supported.json").path("actions").get(0)).deepCopy()
                    .put("effect", "write").put("planning", "unsupported").put("recovery", "provider_undo")
                    .put("idempotency", "coordinator_only");
            undoAction = sourceAction.deepCopy().put("actionId", UNDO).put("recovery", "none").put("completion", completion);
            ObjectNode input = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
            ObjectNode properties = input.putObject("properties"); var required = input.putArray("required");
            for (String field : REFERENCES) { properties.putObject(field).put("type", "string"); required.add(field); }
            undoAction.set("inputSchema", input);
            ObjectNode sourceWire = fixture("invocation.json").put("actionDigest", ContractJson.digest(sourceAction));
            source = new Invocation(contracts, sourceWire); sourceSession = installed(source.context());
            runtime = new HostRuntime(contracts, queue, new HostAuthority() {
                @Override public boolean ready() { return true; }
                @Override public ObjectNode hello() { return ContractJson.newObject(); }
                @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) {
                    assertTrue(queue.isSameThread());
                }
                @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) {
                    assertTrue(queue.isSameThread()); target.preconditionChecks.incrementAndGet();
                    if (!target.expected.get().equals(target.value.get())) {
                        throw new ContractException("FIXTURE_TARGET_DRIFT", "Fixture target differs from its actual precondition");
                    }
                }
            }, (binding, descriptor) -> { }, CLOCK);
            ObjectNode provider = fixture("provider-supported.json"); provider.putArray("actions"); runtime.registerProvider(provider);
            runtime.register(source.bindingId(), sourceAction, (invocation, local) -> {
                local.requireGameThread(); local.beginMutation();
                String before = target.value.get();
                local.captureUndoToken(ContractJson.newObject().put("before", before).put("privateMarker", PRIVATE_MARKER));
                target.value.set("after");
                local.recordEffect(ContractJson.newObject().put("kind", "fixture_memory_write").put("before", before).put("after", "after"));
                return CompletableFuture.completedFuture(complete("after", "recorded"));
            }, OptionalCallbacks.none());
            runtime.register(source.bindingId(), undoAction, (invocation, local) -> {
                throw new IllegalStateException("Recovery must use the registered recover callback");
            }, new OptionalCallbacks(null, poll, null, null, (invocation, token, local) -> recovery.run(invocation, token, local, target)));
            runtime.registerUndo(source.bindingId(), source.actionId(), UNDO);
        }

        private void startSource() {
            var dispatch = runtime.dispatch(sourceSession, source); queue.runNext();
            assertEquals("complete", dispatch.toCompletableFuture().join().status()); assertEquals("after", target.value.get());
            receipt = ContractJson.object(runtime.operation(sourceSession, source.invocationId()).get("undoTokenRecord"));
            assertNotNull(receipt); target.expected.set("after");
        }

        private Invocation recovery(String id, ObjectNode context) {
            ObjectNode wire = source.wire().put("invocationId", id).put("operationId", "operation-" + id)
                    .put("stepId", "undo-step").put("actionId", UNDO).put("actionDigest", ContractJson.digest(undoAction));
            ObjectNode arguments = wire.putObject("arguments");
            for (String field : REFERENCES) arguments.set(field, receipt.get(field).deepCopy());
            wire.set("context", context.deepCopy()); wire.put("contextDigest", ContractJson.contextDigest(context));
            wire.put("argumentsDigest", ContractJson.digest(arguments));
            return new Invocation(contracts, wire);
        }

        private ObjectNode job(Invocation recovery) { return runtime.undoJob(sourceSession, recovery.context(), recovery.invocationId()); }
        @Override public void close() { runtime.close(); }
    }

    private HostSession installed(ObjectNode context) {
        HostSession session = new HostSession(context.path("principalRef").asText(), context.path("environment").path("sessionEpoch").asText(),
                context.path("environment").path("gameInstanceId").asText(), "server", PLAYER, Set.of("diagnostic.read"), true);
        session.installContext(contracts, context); return session;
    }

    private ProviderResult complete(String text, String effects) {
        return ProviderResult.complete(contracts, ContractJson.newObject().put("text", text), effects);
    }

    private static ObjectNode fixture(String name) throws IOException {
        Path file = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(file)) { return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1))); }
    }

    private static Set<String> fields(ObjectNode value) { Set<String> result = new HashSet<>(); value.fieldNames().forEachRemaining(result::add); return result; }
    private static void assertCode(String code, Runnable operation) { assertEquals(code, assertThrows(ContractException.class, operation::run).code()); }
    @FunctionalInterface private interface RecoveryBody {
        CompletionStage<ProviderResult> run(Invocation invocation, ObjectNode privateToken, LocalContext local, FixtureTarget target);
    }
    private static final class FixtureTarget {
        private final AtomicReference<String> value = new AtomicReference<>("before");
        private final AtomicReference<String> expected = new AtomicReference<>("before");
        private final AtomicInteger preconditionChecks = new AtomicInteger();
    }
    private static final class QueueThread implements GameThread {
        private final ArrayDeque<Runnable> queue = new ArrayDeque<>(); private boolean active;
        @Override public boolean isSameThread() { return active; }
        @Override public void execute(Runnable runnable) { queue.add(runnable); }
        private void runNext() {
            active = true; try { queue.removeFirst().run(); } finally { active = false; }
        }
        private int size() { return queue.size(); }
    }
}
