package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.GameThread;
import io.github.daejunnom.mmmm.host.HostAuthority;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 기존 Invocation/HostHello fixture로 목적 route의 거절·수명을 검사한다.
 * 합성 47행은 codec 입력이며 Rust 정본 recipe, 실제 ADMIN, native 실행·profile 증거가 아니다.
 */
final class NativeCalibrationApprovalTest {
    private static final Instant NOW = Instant.parse("2026-10-16T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private final ContractJson contracts = new ContractJson();

    @Test void privateEnvelopeRequiresExactPurposeFortySevenStepsAndOriginalSourceBytes() throws Exception {
        try (Harness harness = new Harness(null, false)) {
            for (String field : List.of("kind", "purpose", "hostEpoch", "suiteDigest", "recipeSha256", "registryGeneration")) {
                ObjectNode changed = harness.manifest.deepCopy().put(field, "invalid");
                assertThrows(ContractException.class, () -> harness.approval(changed, null));
            }
            for (String generation : List.of("0", "01", "-1", "9223372036854775808"))
                assertThrows(ContractException.class, () -> harness.approval(harness.manifest.deepCopy().put("registryGeneration", generation), null));
            ObjectNode count = harness.manifest.deepCopy(); count.withArray("programs").remove(46);
            assertThrows(ContractException.class, () -> harness.approval(count, null));
            ObjectNode duplicate = harness.manifest.deepCopy(); duplicate.withArray("programs").set(1, duplicate.path("programs").get(0).deepCopy());
            assertThrows(ContractException.class, () -> harness.approval(duplicate, null));
            for (String field : List.of("command", "sourceSha256", "sourceBytesHex")) {
                ObjectNode changed = harness.manifest.deepCopy(); first(changed, "programs").put(field, "00");
                assertThrows(ContractException.class, () -> harness.approval(changed, null));
            }
            ObjectNode source = harness.manifest.deepCopy(); first(source, "programs").put("sourceBytesHex", "00".repeat(65537));
            assertThrows(ContractException.class, () -> harness.approval(source, null));
            assertThrows(ContractException.class, () -> harness.approval(harness.manifest.deepCopy().put("verified", true), null));
            assertFalse(harness.session.verifiedWriteProfile()); assertEquals(0, harness.retained.get());
        }
    }

    @Test void unavailablePrepareAndDispatchDoNotConsumeTheExistingPlanOrRetainAnInvocation() throws Exception {
        try (Harness harness = new Harness(null, false)) {
            for (String operation : List.of("first-operation", "second-operation")) {
                ObjectNode invocation = harness.wire(0).put("operationId", operation);
                for (String method : List.of("prepare", "dispatch")) assertEquals("CALIBRATION_RUNNER_UNAVAILABLE", harness.call(method, invocation).path("error").path("code").asText());
            }
            assertUnclaimed(harness.grant); assertEquals(0, harness.retained.get());
            assertEquals("INVOCATION_UNKNOWN", harness.call("operation.get", harness.wire(0)).path("error").path("code").asText());
            assertEquals("INVOCATION_UNKNOWN", harness.call("operation.cancel", harness.wire(0)).path("error").path("code").asText());
            assertFalse(harness.session.verifiedWriteProfile());
        }
    }

    @Test void realRunnerReadinessFailureAndWrongPinsCannotEnterExecuteOrClaimTheOperation() throws Exception {
        AtomicInteger ready = new AtomicInteger(); var runner = new RejectingRunner(ready);
        try (Harness harness = new Harness(runner, false)) {
            for (String method : List.of("prepare", "dispatch")) assertEquals("CALIBRATION_SOURCE_UNAVAILABLE", harness.call(method, harness.wire(0)).path("error").path("code").asText());
            assertEquals(2, ready.get()); assertUnclaimed(harness.grant); assertEquals(0, harness.retained.get());
            ObjectNode changed = harness.wire(0); changed.withObject("arguments").put("command", "say not-the-recipe");
            changed.put("argumentsDigest", ContractJson.digest(changed.path("arguments")));
            assertEquals("CALIBRATION_APPROVAL_MISMATCH", harness.call("dispatch", changed).path("error").path("code").asText());
            assertEquals(2, ready.get()); assertUnclaimed(harness.grant);
        }
    }

    @Test void originalReplyCancellationAndRouteCloseStopLateQueuedWorkBeforeReadiness() throws Exception {
        AtomicInteger ready = new AtomicInteger();
        try (Harness harness = new Harness(new RejectingRunner(ready), true)) {
            var cancelled = harness.begin("dispatch", harness.wire(0)); assertTrue(cancelled.cancel(false));
            harness.drain(); assertEquals(0, ready.get()); assertUnclaimed(harness.grant); assertEquals(0, harness.retained.get());
            var revoked = harness.begin("prepare", harness.wire(1)); harness.grant.close(); harness.drain();
            assertEquals("CALIBRATION_APPROVAL_MISMATCH", revoked.join().path("error").path("code").asText());
            assertEquals(0, ready.get()); assertUnclaimed(harness.grant); assertEquals(0, harness.retained.get());
        }
    }

    @Test void failedRunnerStagesAndReadinessKeepTheirOriginalAndCurrentSourceCauses() throws Exception {
        var execute = new CompletableFuture<ProviderResult>();
        var executions = new AtomicReference<>(execute);
        var poll = new CompletableFuture<ObjectNode>(); var cancel = new CompletableFuture<ObjectNode>();
        var readiness = new AtomicReference<Runnable>();
        var runner = new RejectingRunner(new AtomicInteger()) {
            @Override public ObjectNode ready(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
                control.checkpoint(); Runnable hook = readiness.get(); if (hook != null) hook.run();
                // This synthetic handoff admits no real source or game effect.
                // Every execution/query stage below completes only with failure.
                return ContractJson.newObject().put("fixtureOnly", true);
            }
            @Override public CompletionStage<ProviderResult> execute(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) { return executions.get(); }
            @Override public CompletionStage<ObjectNode> poll(Invocation original, NativeCalibrationApproval.Control control) { return poll; }
            @Override public CompletionStage<ObjectNode> cancel(Invocation original, NativeCalibrationApproval.Control control) { return cancel; }
        };
        try (Harness harness = new Harness(runner, false)) {
            ObjectNode wire = harness.wire(0);
            var dispatch = harness.begin("dispatch", wire); assertFalse(dispatch.isDone());
            assertEquals(1, harness.retained.get());
            ContractException executeFailure = new ContractException("FIXTURE_EXECUTE_FAILED", "합성 stage 오류");
            ContractException sourceFailure = new ContractException("FIXTURE_SOURCE_REVOKED", "합성 현재 source 철회");
            int before = harness.sourceChecks.get(); harness.sourceFailure.set(sourceFailure);
            execute.completeExceptionally(executeFailure);
            assertEquals("FIXTURE_EXECUTE_FAILED", dispatch.join().path("error").path("code").asText());
            assertArrayEquals(new Throwable[] {sourceFailure}, executeFailure.getSuppressed());
            assertTrue(harness.sourceChecks.get() > before);
            for (String method : List.of("operation.get", "operation.cancel")) {
                harness.sourceFailure.set(null);
                var response = harness.begin(method, wire); assertFalse(response.isDone());
                ContractException original = new ContractException("FIXTURE_QUERY_FAILED", "합성 원 query 오류");
                ContractException current = new ContractException("FIXTURE_SOURCE_REVOKED", "합성 현재 source 철회");
                before = harness.sourceChecks.get(); harness.sourceFailure.set(current);
                (method.equals("operation.get") ? poll : cancel).completeExceptionally(original);
                assertEquals("FIXTURE_QUERY_FAILED", response.join().path("error").path("code").asText());
                assertArrayEquals(new Throwable[] {current}, original.getSuppressed());
                assertTrue(harness.sourceChecks.get() > before);
            }
            for (String method : List.of("prepare", "dispatch")) {
                harness.sourceFailure.set(null);
                ContractException original = new ContractException("FIXTURE_READY_FAILED", "합성 원 readiness 오류");
                ContractException current = new ContractException("FIXTURE_SOURCE_REVOKED", "합성 현재 source 철회");
                readiness.set(() -> { harness.sourceFailure.set(current); throw original; });
                assertEquals("FIXTURE_READY_FAILED", harness.call(method, harness.wire(1)).path("error").path("code").asText());
                assertArrayEquals(new Throwable[] {current}, original.getSuppressed());
                assertEquals(1, harness.retained.get());
            }
            readiness.set(null); harness.sourceFailure.set(null);
            var lateStage = new CompletableFuture<ProviderResult>(); executions.set(lateStage);
            var stopped = harness.begin("dispatch", harness.wire(1)); assertFalse(stopped.isDone());
            assertTrue(stopped.cancel(false));
            ContractException original = new ContractException("FIXTURE_EXECUTE_FAILED", "합성 늦은 stage 오류");
            lateStage.completeExceptionally(original);
            assertTrue(stopped.isCancelled()); assertEquals(1, original.getSuppressed().length);
            assertEquals("CANCELLATION_REQUESTED", ((ContractException) original.getSuppressed()[0]).code());
            assertFalse(harness.session.verifiedWriteProfile());
        }
    }

    private static class RejectingRunner implements NativeCalibrationApproval.Runner {
        private final AtomicInteger ready;
        private RejectingRunner(AtomicInteger ready) { this.ready = ready; }
        @Override public ObjectNode ready(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
            control.checkpoint(); ready.incrementAndGet(); throw new ContractException("CALIBRATION_SOURCE_UNAVAILABLE", "합성 fixture에는 실제 loaded function이 없습니다");
        }
        @Override public CompletionStage<ProviderResult> execute(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) { return fail("준비 거절 뒤 execute를 호출하면 안 됩니다"); }
        @Override public CompletionStage<ObjectNode> poll(Invocation original, NativeCalibrationApproval.Control control) { return fail("수락되지 않은 원 Invocation을 poll하면 안 됩니다"); }
        @Override public CompletionStage<ObjectNode> cancel(Invocation original, NativeCalibrationApproval.Control control) { return fail("수락되지 않은 원 Invocation을 cancel하면 안 됩니다"); }
        @Override public NativeCalibrationSource.IssuedReceipt lookup(Invocation original, NativeCalibrationApproval.Control control) { return fail("실제 dispatch 없이 receipt를 만들면 안 됩니다"); }
    }

    private final class Harness implements AutoCloseable {
        private final ObjectNode base, manifest;
        private final HostSession session;
        private final AtomicInteger retained = new AtomicInteger();
        private final AtomicInteger sourceChecks = new AtomicInteger();
        private final AtomicReference<ContractException> sourceFailure = new AtomicReference<>();
        private final List<Runnable> queued = new ArrayList<>();
        private final boolean queue;
        private final HostRuntime runtime;
        private final NativeCalibrationApproval grant;
        private final HostDispatcher dispatcher;
        private Harness(NativeCalibrationApproval.Runner runner, boolean queue) throws IOException {
            this.queue = queue; base = fixture("invocation.json");
            base.put("deadlineAt", NOW.plusSeconds(20).toString()); base.put("actionId", "mmmm:command_execute");
            ObjectNode context = ContractJson.object(base.path("context"));
            session = new HostSession(context.path("principalRef").asText(), context.path("environment").path("sessionEpoch").asText(),
                    context.path("environment").path("gameInstanceId").asText(), "server", UUID.randomUUID(), NativeCalibrationApproval.READ_PERMISSIONS, false);
            session.installContext(contracts, context); manifest = manifest();
            ObjectNode hello = fixture("host-hello.json");
            GameThread thread = new GameThread() {
                @Override public boolean isSameThread() { return true; }
                @Override public void execute(Runnable action) { action.run(); }
            };
            HostAuthority authority = new HostAuthority() {
                @Override public boolean ready() { return true; }
                @Override public ObjectNode hello() { return hello.deepCopy(); }
                @Override public void check(HostSession owner, ObjectNode installed, Set<String> permissions, boolean write) { fail("일반 runtime authority를 우회 수단으로 사용하면 안 됩니다"); }
                @Override public void checkPreconditions(HostSession owner, ObjectNode installed, ObjectNode arguments) { fail("일반 mutation을 호출하면 안 됩니다"); }
            };
            runtime = new HostRuntime(contracts, thread, authority, (binding, descriptor) -> { }, CLOCK);
            grant = approval(manifest, runner);
            // fixture callback은 실제 ADMIN 증거가 아니다. production에서는 원 bridge EOF 뒤 host만 활성화한다.
            grant.activateAfterBridge(session, grant.selectionDigest(), grant.manifestDigest(), () -> { });
            dispatcher = new HostDispatcher(contracts, runtime, (owner, installed, payload, control) -> fail("inspect에서 실행하면 안 됩니다"), CLOCK, grant);
            dispatcher.handle(session, request("hello", null)).toCompletableFuture().join();
        }
        private NativeCalibrationApproval approval(ObjectNode input, NativeCalibrationApproval.Runner runner) {
            return new NativeCalibrationApproval(contracts, input, session, CLOCK, new NativeCalibrationApproval.Tasks() {
                @Override public <T> CompletionStage<T> submit(Supplier<T> action) {
                    var result = new CompletableFuture<T>(); Runnable work = () -> {
                        try { result.complete(action.get()); } catch (RuntimeException failure) { result.completeExceptionally(failure); }
                    };
                    if (queue) queued.add(work); else work.run(); return result.minimalCompletionStage();
                }
            }, (owner, context, original, sources) -> {
                original.run(); owner.checkOpen();
                if (sources) {
                    sourceChecks.incrementAndGet(); ContractException failure = sourceFailure.get(); if (failure != null) throw failure;
                }
            }, original -> retained.incrementAndGet(), runner);
        }
        private ObjectNode wire(int index) {
            ObjectNode wire = base.deepCopy().put("stepId", "step-" + index).put("invocationId", "invocation-" + index);
            wire.set("arguments", ContractJson.newObject().put("command", "function mmmm_calibration:case_" + index + "/fixture"));
            wire.put("argumentsDigest", ContractJson.digest(wire.path("arguments"))); return wire;
        }
        private ObjectNode manifest() {
            ObjectNode context = ContractJson.object(base.path("context"));
            ObjectNode result = ContractJson.newObject().put("kind", "native_calibration_approval").put("purpose", NativeCalibrationApproval.PURPOSE)
                    .put("selectionDigest", "a".repeat(64)).put("hostEpoch", session.epoch()).put("registryGeneration", "31")
                    .put("runtimeSourceFactsDigest", "b".repeat(64)).put("suiteDigest", "c".repeat(64)).put("recipeSha256", "c".repeat(64));
            ObjectNode inner = result.putObject("plan").put("kind", "native_plan_approval").put("protocolVersion", ContractJson.VERSION)
                    .put("principalId", session.principalRef()).put("projectId", context.path("projectId").asText())
                    .put("planId", "plan-fixture").put("planHash", "d".repeat(64)).put("policyRevision", context.path("policyRevision").asText())
                    .put("expiresAt", NOW.plusSeconds(60).toString());
            ObjectNode pin = inner.putArray("contextPins").addObject().put("contextId", context.path("contextId").asText()).put("contextDigest", context.path("contextDigest").asText());
            pin.set("environment", context.path("environment").deepCopy()); inner.putArray("nativeExecutions");
            var steps = inner.putArray("steps"); var programs = result.putArray("programs");
            byte[] source = "scoreboard players set #ok fixture 0\n".getBytes(StandardCharsets.UTF_8);
            for (int index = 0; index < 47; index++) {
                ObjectNode wire = wire(index), step = steps.addObject();
                for (String field : Set.of("stepId", "bindingId", "actionId", "actionDigest", "implementationDigest", "argumentsDigest", "contextDigest")) step.set(field, wire.path(field).deepCopy());
                step.put("contextId", context.path("contextId").asText()); step.putArray("resourcesRead"); step.putArray("resourcesWritten"); step.putArray("preconditions");
                ObjectNode program = programs.addObject().put("stepId", "step-" + index).put("caseId", "case_" + index)
                        .put("functionId", "mmmm_calibration:case_" + index + "/fixture").put("command", wire.path("arguments").path("command").asText())
                        .put("programDigest", "e".repeat(64)).put("sourceSha256", ContractJson.sha256(source)).put("sourceBytesHex", HexFormat.of().formatHex(source));
                program.putObject("readbackAddresses").put("caseId", "case_" + index).put("function", program.path("functionId").asText());
            }
            return result;
        }
        private ObjectNode request(String method, ObjectNode wire) {
            ObjectNode request = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION).put("requestId", "request-fixture")
                    .put("method", method).put("deadlineAt", NOW.plusSeconds(30).toString());
            if (wire == null) { request.putNull("contextId"); request.putObject("payload"); }
            else {
                request.put("contextId", wire.path("context").path("contextId").asText());
                if (Set.of("prepare", "dispatch").contains(method)) request.set("payload", wire.deepCopy());
                else request.putObject("payload").put("invocationId", wire.path("invocationId").asText());
            }
            return request;
        }
        private CompletableFuture<ObjectNode> begin(String method, ObjectNode wire) { return dispatcher.handle(session, request(method, wire)).toCompletableFuture(); }
        private ObjectNode call(String method, ObjectNode wire) { return begin(method, wire).join(); }
        private void drain() { while (!queued.isEmpty()) queued.removeFirst().run(); }
        @Override public void close() { grant.close(); session.close(); runtime.close(); }
    }
    private static void assertUnclaimed(NativeCalibrationApproval approval) throws Exception {
        Field original = NativeCalibrationApproval.class.getDeclaredField("plan"); original.setAccessible(true);
        NativePlanApproval plan = (NativePlanApproval) original.get(approval);
        for (String name : List.of("reservations", "invocationSteps")) {
            Field field = NativePlanApproval.class.getDeclaredField(name); field.setAccessible(true); assertTrue(((Map<?, ?>) field.get(plan)).isEmpty());
        }
        Field operation = NativePlanApproval.class.getDeclaredField("operationId"); operation.setAccessible(true); assertNull(operation.get(plan));
    }
    private static ObjectNode first(ObjectNode value, String name) { return ContractJson.object(value.path(name).get(0)); }
    private static ObjectNode fixture(String name) throws IOException {
        Path path = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(path)) { return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1))); }
    }
}
