package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.GameThread;
import io.github.daejunnom.mmmm.host.HostAuthority;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.host.NativeInvocationReservations;
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
            for (String field : List.of("commands", "preseedEndIndex", "selectedCommandStageIndex", "initializationCommands", "cleanupCommands", "targetBindings")) {
                ObjectNode missing = harness.manifest.deepCopy(); first(missing, "programs").remove(field);
                assertThrows(ContractException.class, () -> harness.approval(missing, null));
            }
            for (String field : List.of("preseedEndIndex", "selectedCommandStageIndex")) {
                ObjectNode negative = harness.manifest.deepCopy(); first(negative, "programs").put(field, -1);
                assertThrows(ContractException.class, () -> harness.approval(negative, null));
                ObjectNode decimal = harness.manifest.deepCopy(); first(decimal, "programs").put(field, 1.0);
                assertThrows(ContractException.class, () -> harness.approval(decimal, null));
                ObjectNode coerced = harness.manifest.deepCopy(); first(coerced, "programs").put(field, "1");
                assertThrows(ContractException.class, () -> harness.approval(coerced, null));
                ObjectNode oversized = harness.manifest.deepCopy(); first(oversized, "programs").put(field, 2147483648L);
                assertThrows(ContractException.class, () -> harness.approval(oversized, null));
            }
            ObjectNode prefix = harness.manifest.deepCopy(); first(prefix, "programs").put("preseedEndIndex", 2);
            assertThrows(ContractException.class, () -> harness.approval(prefix, null));
            ObjectNode selected = harness.manifest.deepCopy(); first(selected, "programs").put("selectedCommandStageIndex", 2);
            assertThrows(ContractException.class, () -> harness.approval(selected, null));
            ObjectNode zero = harness.manifest.deepCopy(); first(zero, "programs").put("preseedEndIndex", 0).put("selectedCommandStageIndex", 0);
            try (NativeCalibrationApproval comparisonOnly = harness.approval(zero, null)) {
                assertNotNull(comparisonOnly); // codec 범위 검사이며 Rust 원 recipe의 수치나 실행 승인이 아니다.
            }
            for (String field : List.of("commands", "initializationCommands", "cleanupCommands")) {
                ObjectNode wrongType = harness.manifest.deepCopy(); first(wrongType, "programs").put(field, "command");
                assertThrows(ContractException.class, () -> harness.approval(wrongType, null));
                ObjectNode wrongEntry = harness.manifest.deepCopy(); first(wrongEntry, "programs").putArray(field).add(1);
                assertThrows(ContractException.class, () -> harness.approval(wrongEntry, null));
                for (String command : List.of("", "# comment", "say one\nsay two", "say one\rsay two", "say\0two", "é".repeat(4097), "\uD800")) {
                    ObjectNode invalidCommand = harness.manifest.deepCopy(); first(invalidCommand, "programs").putArray(field).add(command);
                    assertThrows(ContractException.class, () -> harness.approval(invalidCommand, null));
                }
                ObjectNode oversized = harness.manifest.deepCopy(); var commands = first(oversized, "programs").putArray(field);
                for (int index = 0; index < 4097; index++) commands.add("say bounded");
                assertThrows(ContractException.class, () -> harness.approval(oversized, null));
            }
            ObjectNode empty = harness.manifest.deepCopy(); first(empty, "programs").putArray("commands");
            assertThrows(ContractException.class, () -> harness.approval(empty, null));
            ObjectNode legacy = harness.manifest.deepCopy().put("kind", "native_calibration_approval");
            assertThrows(ContractException.class, () -> harness.approval(legacy, null));
            ObjectNode oldAddresses = harness.manifest.deepCopy(); first(oldAddresses, "programs").putObject("readbackAddresses");
            assertThrows(ContractException.class, () -> harness.approval(oldAddresses, null));
            for (String field : List.of("resourcesRead", "resourcesWritten", "preconditions")) {
                ObjectNode missing = harness.manifest.deepCopy(); first(missing.withObject("plan"), "steps").withArray(field).remove(1);
                assertThrows(ContractException.class, () -> harness.approval(missing, null));
            }
            ObjectNode wrongTarget = harness.manifest.deepCopy(); first(first(wrongTarget, "programs"), "targetBindings").put("targetId", "resource-state");
            assertThrows(ContractException.class, () -> harness.approval(wrongTarget, null));
            ObjectNode wrongAddress = harness.manifest.deepCopy(); first(first(wrongAddress, "programs"), "targetBindings").put("objective", "unapproved");
            assertThrows(ContractException.class, () -> harness.approval(wrongAddress, null));
            ObjectNode wrongCoverage = harness.manifest.deepCopy(); first(first(wrongCoverage.withObject("plan"), "steps"), "preconditions").put("coverage", "partial");
            assertThrows(ContractException.class, () -> harness.approval(wrongCoverage, null));
            ObjectNode wrongSubtree = harness.manifest.deepCopy();
            ContractJson.object(first(wrongSubtree, "programs").path("targetBindings").get(1)).putArray("ownedSubtrees").add("inputs").add("unowned");
            assertThrows(ContractException.class, () -> harness.approval(wrongSubtree, null));
            ObjectNode ordinaryAction = harness.manifest.deepCopy();
            first(ordinaryAction.withObject("plan"), "steps").put("actionId", "mmmm:command_execute");
            assertThrows(ContractException.class, () -> harness.approval(ordinaryAction, null));
            ObjectNode total = harness.manifest.deepCopy(); var commands = first(total, "programs").putArray("commands");
            for (int index = 0; index < 4090; index++) commands.add("say bounded");
            assertThrows(ContractException.class, () -> harness.approval(total, null));
            assertThrows(ContractException.class, () -> harness.approval(harness.manifest.deepCopy().put("verified", true), null));
            assertFalse(harness.session.verifiedWriteProfile()); assertEquals(0, harness.retained.get());
        }
    }

    @Test void programComparisonInputsRetainOriginalOrderAndCannotBeChangedThroughGetters() throws Exception {
        var observed = new AtomicReference<NativeCalibrationApproval.Program>();
        var runner = new RejectingRunner(new AtomicInteger()) {
            @Override public NativeCalibrationPrepared ready(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
                observed.set(program); return super.ready(original, program, control);
            }
        };
        try (Harness harness = new Harness(runner, false)) {
            assertEquals("CALIBRATION_SOURCE_UNAVAILABLE", harness.call("prepare", harness.wire(0)).path("error").path("code").asText());
            NativeCalibrationApproval.Program program = observed.get(); assertNotNull(program);
            List<String> commands = List.of("scoreboard players set #ok fixture 0", "scoreboard players get #ok fixture");
            List<String> initialization = List.of("scoreboard objectives add fixture dummy");
            List<String> cleanup = List.of("scoreboard objectives remove fixture", "data remove storage mmmm_calibration:fixture states", "data remove storage mmmm_calibration:fixture inputs");
            assertEquals(commands, program.commands()); assertEquals(1, program.preseedEndIndex());
            assertEquals(1, program.selectedCommandStageIndex()); assertEquals(initialization, program.initializationCommands());
            assertEquals(cleanup, program.cleanupCommands());
            for (List<String> immutable : List.of(program.commands(), program.initializationCommands(), program.cleanupCommands()))
                assertThrows(UnsupportedOperationException.class, () -> immutable.set(0, "changed"));
            assertEquals(2, program.targetBindings().size());
            assertEquals(program.resourcesRead(), program.resourcesWritten());
            assertEquals(program.targetBindings().get(0).targetId(), program.resourcesRead().get(0));
            assertEquals(program.targetBindings().get(1).targetId(), program.resourcesRead().get(1));
            for (List<String> immutable : List.of(program.resourcesRead(), program.resourcesWritten(), program.targetBindings().get(1).ownedSubtrees()))
                assertThrows(UnsupportedOperationException.class, () -> immutable.set(0, "changed"));
            assertThrows(UnsupportedOperationException.class, () -> program.targetBindings().clear());
            byte[] source = program.sourceBytes(); source[0] = 0;
            assertEquals((byte) '#', program.sourceBytes()[0]);
            ObjectNode original = first(harness.manifest, "programs");
            original.putArray("commands").add("changed"); original.putArray("initializationCommands"); original.putArray("cleanupCommands");
            assertEquals(commands, program.commands()); assertEquals(initialization, program.initializationCommands()); assertEquals(cleanup, program.cleanupCommands());
            assertUnclaimed(harness.grant); assertEquals(0, harness.retained.get()); assertFalse(harness.session.verifiedWriteProfile());
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
            AtomicInteger observations = new AtomicInteger(); ObjectNode original = harness.wire(0);
            assertEquals("INVOCATION_UNKNOWN", assertThrows(ContractException.class, () -> harness.grant.observeState(harness.session,
                    ContractJson.object(original.path("context")), original.path("invocationId").asText(), ContractJson.digest(original),
                    null, (invocation, program, control) -> { observations.incrementAndGet(); return null; })).code());
            assertEquals(0, observations.get(), "An unaccepted state query must not observe targets or manufacture an original claim");
            assertFalse(harness.session.verifiedWriteProfile());
        }
    }

    @Test void factualNativeOutputRetainsNoCallbackAndMultipleCallbackNullReturns() throws Exception {
        // Pure closed output codec only; this does not create Prepared, Accepted
        // or native execution evidence from these synthetic JSON values.
        var validate = NativeCalibrationApproval.class.getDeclaredMethod("nativeOutput", ObjectNode.class); validate.setAccessible(true);
        for (int count : List.of(0, 2, 256)) {
            ObjectNode output = ContractJson.newObject().put("completionClaim", "native_function_queue_observed")
                    .put("nativeCallbackCount", count).putNull("nativeCallbackReturn");
            assertDoesNotThrow(() -> validate.invoke(null, output));
            output.put("nativeCallbackReturn", 0);
            assertInstanceOf(ContractException.class, assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> validate.invoke(null, output)).getCause());
        }
        ObjectNode single = ContractJson.newObject().put("completionClaim", "native_function_queue_observed")
                .put("nativeCallbackCount", 1).put("nativeCallbackReturn", Integer.MIN_VALUE);
        assertDoesNotThrow(() -> validate.invoke(null, single)); single.put("nativeCallbackReturn", Integer.MAX_VALUE);
        assertDoesNotThrow(() -> validate.invoke(null, single));
        for (ObjectNode invalid : List.of(single.deepCopy().putNull("nativeCallbackReturn"), single.deepCopy().put("nativeCallbackReturn", 2147483648L),
                single.deepCopy().put("nativeCallbackCount", -1), single.deepCopy().put("nativeCallbackCount", 257),
                single.deepCopy().put("nativeCallbackCount", 1.0), single.deepCopy().put("completionClaim", "complete"),
                single.deepCopy().put("success", true))) {
            assertInstanceOf(ContractException.class, assertThrows(java.lang.reflect.InvocationTargetException.class,
                    () -> validate.invoke(null, invalid)).getCause());
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

    @Test void nullOrJsonOnlyReadinessCannotAdmitAnExternalTargetInvocation() throws Exception {
        var runner = new RejectingRunner(new AtomicInteger()) {
            @Override public NativeCalibrationPrepared ready(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
                control.checkpoint(); return null;
            }
        };
        try (Harness harness = new Harness(runner, false)) {
            for (String method : List.of("prepare", "dispatch"))
                assertEquals("CALIBRATION_APPROVAL_MISMATCH", harness.call(method, harness.wire(0)).path("error").path("code").asText());
            assertUnclaimed(harness.grant); assertEquals(0, harness.retained.get());
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

    @Test void failedFinalizationAndReadinessKeepTheirOriginalAndCurrentSourceCauses() throws Exception {
        // The actual Prepared capability has no synthetic positive factory.
        // Exercise the shared production failure finalizer directly instead of
        // admitting an Invocation with a JSON-only fake readiness result.
        var finalize = NativeCalibrationApproval.class.getDeclaredMethod("completeChecked", CompletableFuture.class,
                Throwable.class, Supplier.class, Runnable.class);
        finalize.setAccessible(true);
        for (String stage : List.of("execute", "poll", "cancel")) {
            var result = new CompletableFuture<ObjectNode>();
            ContractException original = new ContractException("FIXTURE_STAGE_FAILED", stage);
            ContractException current = new ContractException("FIXTURE_SOURCE_REVOKED", "합성 현재 source 철회");
            finalize.invoke(null, result, original, (Supplier<ObjectNode>) () -> fail("실패 stage는 성공값을 읽으면 안 됩니다"),
                    (Runnable) () -> { throw current; });
            assertSame(original, assertThrows(java.util.concurrent.CompletionException.class, result::join).getCause());
            assertArrayEquals(new Throwable[] {current}, original.getSuppressed());
        }
        var stopped = new CompletableFuture<ObjectNode>(); assertTrue(stopped.cancel(false));
        ContractException late = new ContractException("FIXTURE_STAGE_FAILED", "합성 늦은 stage 오류");
        ContractException cancellation = new ContractException("CANCELLATION_REQUESTED", "합성 원 요청 취소");
        finalize.invoke(null, stopped, late, (Supplier<ObjectNode>) ContractJson::newObject,
                (Runnable) () -> { throw cancellation; });
        assertTrue(stopped.isCancelled()); assertArrayEquals(new Throwable[] {cancellation}, late.getSuppressed());
        var readiness = new AtomicReference<Runnable>();
        var runner = new RejectingRunner(new AtomicInteger()) {
            @Override public NativeCalibrationPrepared ready(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
                control.checkpoint(); Runnable hook = readiness.get(); if (hook != null) hook.run();
                return super.ready(original, program, control);
            }
        };
        try (Harness harness = new Harness(runner, false)) {
            for (String method : List.of("prepare", "dispatch")) {
                harness.sourceFailure.set(null);
                ContractException original = new ContractException("FIXTURE_READY_FAILED", "합성 원 readiness 오류");
                ContractException current = new ContractException("FIXTURE_SOURCE_REVOKED", "합성 현재 source 철회");
                readiness.set(() -> { harness.sourceFailure.set(current); throw original; });
                int before = harness.sourceChecks.get();
                assertEquals("FIXTURE_READY_FAILED", harness.call(method, harness.wire(1)).path("error").path("code").asText());
                assertArrayEquals(new Throwable[] {current}, original.getSuppressed());
                assertTrue(harness.sourceChecks.get() > before); assertEquals(0, harness.retained.get());
            }
            assertUnclaimed(harness.grant);
            assertFalse(harness.session.verifiedWriteProfile());
        }
    }

    private static class RejectingRunner implements NativeCalibrationApproval.Runner {
        private final AtomicInteger ready;
        private RejectingRunner(AtomicInteger ready) { this.ready = ready; }
        @Override public NativeCalibrationPrepared ready(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
            control.checkpoint(); ready.incrementAndGet(); throw new ContractException("CALIBRATION_SOURCE_UNAVAILABLE", "합성 fixture에는 실제 loaded function이 없습니다");
        }
        @Override public CompletionStage<ProviderResult> execute(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) { return fail("준비 거절 뒤 execute를 호출하면 안 됩니다"); }
        @Override public CompletionStage<ObjectNode> poll(Invocation original, NativeCalibrationApproval.Control control) { return fail("수락되지 않은 원 Invocation을 poll하면 안 됩니다"); }
        @Override public CompletionStage<ObjectNode> cancel(Invocation original, NativeCalibrationApproval.Control control) { return fail("수락되지 않은 원 Invocation을 cancel하면 안 됩니다"); }
        @Override public NativeCalibrationRunFacts lookup(Invocation original, NativeCalibrationApproval.Control control) { return fail("실제 dispatch 없이 receipt를 만들면 안 됩니다"); }
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
            base.put("deadlineAt", NOW.plusSeconds(20).toString()); base.put("actionId", "mmmm:calibration_command_execute");
            ObjectNode context = ContractJson.object(base.path("context"));
            var targets = context.withObject("scope").withArray("externalTargetIds");
            for (int index = 0; index < 47; index++) {
                String suffix = index == 0 ? "" : Integer.toString(index);
                targets.add("calibration-objective-fixture" + suffix);
                targets.add("calibration-storage-" + ContractJson.sha256(("mmmm_calibration:fixture" + suffix).getBytes(StandardCharsets.UTF_8)));
            }
            context.put("contextDigest", ContractJson.contextDigest(context)); base.put("contextDigest", context.path("contextDigest").asText());
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
            ObjectNode result = ContractJson.newObject().put("kind", "native_calibration_approval/2").put("purpose", NativeCalibrationApproval.PURPOSE)
                    .put("selectionDigest", "a".repeat(64)).put("hostEpoch", session.epoch()).put("registryGeneration", "31")
                    .put("runtimeSourceFactsDigest", "b".repeat(64)).put("suiteDigest", "c".repeat(64)).put("recipeSha256", "c".repeat(64));
            ObjectNode inner = result.putObject("plan").put("kind", "native_plan_approval").put("protocolVersion", ContractJson.VERSION)
                    .put("principalId", session.principalRef()).put("projectId", context.path("projectId").asText())
                    .put("planId", "plan-fixture").put("planHash", "d".repeat(64)).put("policyRevision", context.path("policyRevision").asText())
                    .put("expiresAt", NOW.plusSeconds(60).toString());
            ObjectNode pin = inner.putArray("contextPins").addObject().put("contextId", context.path("contextId").asText()).put("contextDigest", context.path("contextDigest").asText());
            pin.set("environment", context.path("environment").deepCopy()); inner.putArray("nativeExecutions");
            var steps = inner.putArray("steps"); var programs = result.putArray("programs");
            byte[] source = "# storage-only comparison fixture\nscoreboard players set #ok fixture 0\nscoreboard players get #ok fixture\n".getBytes(StandardCharsets.UTF_8);
            for (int index = 0; index < 47; index++) {
                ObjectNode wire = wire(index), step = steps.addObject();
                for (String field : Set.of("stepId", "bindingId", "actionId", "actionDigest", "implementationDigest", "argumentsDigest", "contextDigest")) step.set(field, wire.path(field).deepCopy());
                String suffix = index == 0 ? "" : Integer.toString(index);
                String objective = "fixture" + suffix, storage = "mmmm_calibration:fixture" + suffix;
                String objectiveTarget = "calibration-objective-" + objective;
                String storageTarget = "calibration-storage-" + ContractJson.sha256(storage.getBytes(StandardCharsets.UTF_8));
                step.put("contextId", context.path("contextId").asText());
                step.putArray("resourcesRead").add(objectiveTarget).add(storageTarget);
                step.putArray("resourcesWritten").add(objectiveTarget).add(storageTarget);
                var conditions = step.putArray("preconditions");
                for (String target : List.of(objectiveTarget, storageTarget)) conditions.addObject().put("kind", "resource_hash")
                        .put("subject", target).put("expected", "f".repeat(64)).put("coverage", "full_target");
                ObjectNode program = programs.addObject().put("stepId", "step-" + index).put("caseId", "case_" + index)
                        .put("functionId", "mmmm_calibration:case_" + index + "/fixture").put("command", wire.path("arguments").path("command").asText())
                        .put("programDigest", ContractJson.sha256(source)).put("sourceSha256", ContractJson.sha256(source)).put("sourceBytesHex", HexFormat.of().formatHex(source))
                        .put("preseedEndIndex", 1).put("selectedCommandStageIndex", 1);
                program.putArray("commands").add("scoreboard players set #ok fixture 0").add("scoreboard players get #ok fixture");
                program.putArray("initializationCommands").add("scoreboard objectives add fixture dummy");
                program.putArray("cleanupCommands").add("scoreboard objectives remove fixture")
                        .add("data remove storage mmmm_calibration:fixture states").add("data remove storage mmmm_calibration:fixture inputs");
                var targets = program.putArray("targetBindings");
                targets.addObject().put("targetId", objectiveTarget).put("kind", "objective").put("objective", objective);
                targets.addObject().put("targetId", storageTarget).put("kind", "owned_storage").put("storage", storage)
                        .putArray("ownedSubtrees").add("inputs").add("invocation");
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
        Field original = NativeCalibrationApproval.class.getDeclaredField("reservations"); original.setAccessible(true);
        NativeInvocationReservations plan = (NativeInvocationReservations) original.get(approval);
        for (String name : List.of("reservations", "invocationSteps")) {
            Field field = NativeInvocationReservations.class.getDeclaredField(name); field.setAccessible(true); assertTrue(((Map<?, ?>) field.get(plan)).isEmpty());
        }
        Field operation = NativeInvocationReservations.class.getDeclaredField("operationId"); operation.setAccessible(true); assertNull(operation.get(plan));
    }
    private static ObjectNode first(ObjectNode value, String name) { return ContractJson.object(value.path(name).get(0)); }
    private static ObjectNode fixture(String name) throws IOException {
        Path path = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(path)) { return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1))); }
    }
}
