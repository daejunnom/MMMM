package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.io.IOException;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 원본 host fixture를 사용한 요청 제어 검사이며 실제 게임/네이티브 승인 근거가 아니다. */
final class HostInspectionControlTest {
    private static final Instant NOW = Instant.parse("2026-10-15T00:00:00Z");
    @Test void originalWallAndMonotonicBudgetsCannotRestartWhenWallClockMovesBackwards() {
        MutableClock clock = new MutableClock(); AtomicLong nanos = new AtomicLong(100);
        var control = new HostDispatcher.InspectionControl(clock, NOW.plusSeconds(5), NOW, 100, nanos::get);
        assertEquals(NOW.plusSeconds(5), control.deadlineAt()); assertEquals(5000, control.remainingMillis());
        nanos.addAndGet(2_000_000_000L); clock.now = NOW.plusSeconds(2); assertEquals(3000, control.remainingMillis());
        clock.now = NOW.minusSeconds(60); nanos.addAndGet(3_000_000_000L);
        assertEquals("DEADLINE_EXCEEDED", assertThrows(ContractException.class, control::checkpoint).code());
        var wall = new HostDispatcher.InspectionControl(clock, NOW.plusSeconds(5), NOW, nanos.get(), nanos::get);
        clock.now = NOW.plusSeconds(5);
        assertEquals("DEADLINE_EXCEEDED", assertThrows(ContractException.class, wall::checkpoint).code());
    }
    @Test void stoppingOneControlDoesNotCancelAnotherOriginalRequest() {
        MutableClock clock = new MutableClock(); AtomicLong nanos = new AtomicLong();
        var first = new HostDispatcher.InspectionControl(clock, NOW.plusSeconds(5), NOW, 0, nanos::get);
        var second = new HostDispatcher.InspectionControl(clock, NOW.plusSeconds(5), NOW, 0, nanos::get);
        first.stop(); assertEquals("CANCELLATION_REQUESTED", assertThrows(ContractException.class, first::checkpoint).code());
        assertDoesNotThrow(second::checkpoint);
    }
    @Test void stopBeforeOwnerRegistrationReleasesThePrivateFutureExactlyOnce() {
        MutableClock clock = new MutableClock(); AtomicLong nanos = new AtomicLong();
        var control = new HostDispatcher.InspectionControl(clock, NOW.plusSeconds(5), NOW, 0, nanos::get);
        AtomicInteger active = new AtomicInteger(1); AtomicInteger stopped = new AtomicInteger();
        CompletableFuture<ObjectNode> owner = new CompletableFuture<>();
        owner.whenComplete((value, failure) -> active.decrementAndGet());
        control.stop();
        control.whenStopped(() -> { stopped.incrementAndGet(); owner.cancel(false); });
        control.stop();
        assertTrue(owner.isCancelled()); assertEquals(0, active.get()); assertEquals(1, stopped.get());
        assertThrows(IllegalStateException.class, () -> control.whenStopped(() -> fail("Second hook cannot replace its owner")));
    }
    @Test void cancellingAnActualDispatcherReplyStopsOnlyItsPrivateMinimalStageOwner() throws Exception {
        ContractJson contracts = new ContractJson(); MutableClock clock = new MutableClock();
        ObjectNode hello = fixture("host-hello.json"); ObjectNode context = ContractJson.object(fixture("invocation.json").path("context"));
        HostSession session = new HostSession("principal-fixture", "epoch-fixture-01", "game-fixture-01", "server", UUID.randomUUID(), Set.of(), false);
        session.installContext(contracts, context);
        GameThread thread = new GameThread() {
            @Override public boolean isSameThread() { return true; }
            @Override public void execute(Runnable action) { action.run(); }
        };
        HostAuthority authority = new HostAuthority() {
            @Override public boolean ready() { return true; }
            @Override public ObjectNode hello() { return hello.deepCopy(); }
            @Override public void check(HostSession owner, ObjectNode installed, Set<String> permissions, boolean write) { owner.checkOpen(); }
            @Override public void checkPreconditions(HostSession owner, ObjectNode installed, ObjectNode arguments) { }
        };
        List<HostDispatcher.InspectionControl> controls = new ArrayList<>(); List<CompletableFuture<ObjectNode>> work = new ArrayList<>();
        List<CompletionStage<ObjectNode>> views = new ArrayList<>(); List<Runnable> queued = new ArrayList<>();
        List<AtomicInteger> stops = new ArrayList<>(); AtomicInteger active = new AtomicInteger(); AtomicInteger reads = new AtomicInteger();
        try (HostRuntime runtime = new HostRuntime(contracts, thread, authority, (binding, descriptor) -> { }, clock)) {
            HostDispatcher dispatcher = new HostDispatcher(contracts, runtime, (owner, installed, payload, control) -> {
                controls.add(control); CompletableFuture<ObjectNode> pending = new CompletableFuture<>(); work.add(pending);
                AtomicInteger stopped = new AtomicInteger(); stops.add(stopped); active.incrementAndGet();
                pending.whenComplete((value, failure) -> active.decrementAndGet());
                control.whenStopped(() -> { stopped.incrementAndGet(); pending.cancel(false); });
                queued.add(() -> { if (pending.isDone()) return; control.checkpoint(); reads.incrementAndGet(); pending.complete(ContractJson.newObject()); });
                CompletionStage<ObjectNode> view = pending.minimalCompletionStage(); views.add(view); return view;
            }, clock);
            assertEquals("ok", dispatcher.handle(session, request("hello", "hello")).toCompletableFuture().join().path("status").asText());
            var first = dispatcher.handle(session, request("inspect", "inspect-1")).toCompletableFuture();
            var second = dispatcher.handle(session, request("inspect", "inspect-2")).toCompletableFuture();
            assertEquals(NOW.plusSeconds(30), controls.getFirst().deadlineAt());
            assertTrue(views.getFirst().toCompletableFuture().complete(ContractJson.newObject().put("caller", "copy-only")));
            assertFalse(work.getFirst().isDone()); assertEquals(2, active.get());
            assertTrue(first.cancel(false)); assertTrue(work.getFirst().isCancelled());
            assertEquals(1, active.get()); queued.getFirst().run(); assertEquals(0, reads.get());
            assertEquals("CANCELLATION_REQUESTED", assertThrows(ContractException.class, controls.getFirst()::checkpoint).code());
            assertDoesNotThrow(controls.get(1)::checkpoint); assertFalse(work.get(1).isCancelled());
            work.get(1).complete(ContractJson.newObject().put("registry", "fixture-only"));
            assertEquals("ok", second.join().path("status").asText());
            assertFalse(work.get(1).isCancelled()); assertEquals(0, active.get());
            assertEquals(1, stops.getFirst().get()); assertEquals(1, stops.get(1).get());
            assertEquals("CANCELLATION_REQUESTED", assertThrows(ContractException.class, controls.get(1)::checkpoint).code());
            var late = dispatcher.handle(session, request("inspect", "inspect-3")).toCompletableFuture();
            clock.now = NOW.plusSeconds(31);
            work.get(2).complete(ContractJson.newObject().put("registry", "late-fixture-only"));
            assertEquals("error", late.join().path("status").asText());
            assertEquals("DEADLINE_EXCEEDED", late.join().path("error").path("code").asText());
            clock.now = NOW;
            for (int number = 0; number < 16; number++) {
                var raced = dispatcher.handle(session, request("inspect", "race-" + number)).toCompletableFuture();
                int index = work.size() - 1; CompletableFuture<ObjectNode> owner = work.get(index);
                CompletableFuture<Void> start = new CompletableFuture<>();
                var cancel = start.thenRunAsync(() -> raced.cancel(false));
                var complete = start.thenRunAsync(() -> owner.complete(ContractJson.newObject()));
                start.complete(null); CompletableFuture.allOf(cancel, complete).get(5, TimeUnit.SECONDS);
                assertTrue(owner.isDone()); assertEquals(0, active.get()); assertEquals(1, stops.get(index).get());
                assertEquals("CANCELLATION_REQUESTED", assertThrows(ContractException.class, controls.get(index)::checkpoint).code());
                if (!raced.isCancelled()) assertEquals("ok", raced.join().path("status").asText());
                queued.get(index).run(); assertEquals(0, reads.get());
            }
        } finally { session.close(); }
    }
    @Test void installedPurposeOwnsAllInvocationMethodsWithoutAFallbackToTheGeneralRuntime() throws IOException {
        ContractJson contracts = new ContractJson(); MutableClock clock = new MutableClock();
        ObjectNode hello = fixture("host-hello.json"), wire = fixture("invocation.json");
        wire.put("deadlineAt", NOW.plusSeconds(20).toString());
        HostSession session = new HostSession("principal-fixture", "epoch-fixture-01", "game-fixture-01", "server", UUID.randomUUID(), Set.of(), false);
        session.installContext(contracts, wire.path("context"));
        GameThread thread = new GameThread() {
            @Override public boolean isSameThread() { return true; }
            @Override public void execute(Runnable action) { action.run(); }
        };
        HostAuthority authority = new HostAuthority() {
            @Override public boolean ready() { return true; }
            @Override public ObjectNode hello() { return hello.deepCopy(); }
            @Override public void check(HostSession owner, ObjectNode installed, Set<String> permissions, boolean write) { fail("일반 runtime 권한 경로를 선택하면 안 됩니다"); }
            @Override public void checkPreconditions(HostSession owner, ObjectNode installed, ObjectNode arguments) { fail("일반 mutation 경로를 선택하면 안 됩니다"); }
        };
        List<String> calls = new ArrayList<>(); List<HostDispatcher.InspectionControl> controls = new ArrayList<>();
        HostDispatcher.PurposeRoute route = new HostDispatcher.PurposeRoute() {
            private <T> CompletionStage<T> unavailable(String method, HostDispatcher.InspectionControl control) {
                calls.add(method); controls.add(control); control.checkpoint();
                assertEquals(NOW.plusSeconds(30), control.deadlineAt());
                return CompletableFuture.failedFuture(new ContractException("CALIBRATION_RUNNER_UNAVAILABLE", "실제 runner 없음"));
            }
            @Override public CompletionStage<ObjectNode> prepare(HostSession owner, Invocation invocation, HostDispatcher.InspectionControl control) { return unavailable("prepare", control); }
            @Override public CompletionStage<ProviderResult> dispatch(HostSession owner, Invocation invocation, HostDispatcher.InspectionControl control) { return unavailable("dispatch", control); }
            @Override public CompletionStage<ObjectNode> poll(HostSession owner, String id, HostDispatcher.InspectionControl control) { return unavailable("operation.get", control); }
            @Override public CompletionStage<ObjectNode> cancel(HostSession owner, String id, HostDispatcher.InspectionControl control) { return unavailable("operation.cancel", control); }
        };
        try (HostRuntime runtime = new HostRuntime(contracts, thread, authority, (binding, descriptor) -> { }, clock)) {
            HostDispatcher dispatcher = new HostDispatcher(contracts, runtime, (owner, installed, payload, control) -> fail("inspect 실행을 선택하면 안 됩니다"), clock, route);
            dispatcher.handle(session, request("hello", "hello-purpose")).toCompletableFuture().join();
            for (String method : List.of("prepare", "dispatch", "operation.get", "operation.cancel")) {
                ObjectNode request = request(method, "purpose-" + calls.size()).put("contextId", wire.path("context").path("contextId").asText());
                if (Set.of("prepare", "dispatch").contains(method)) request.set("payload", wire.deepCopy());
                else request.withObject("payload").put("invocationId", wire.path("invocationId").asText());
                ObjectNode response = dispatcher.handle(session, request).toCompletableFuture().join();
                assertEquals("CALIBRATION_RUNNER_UNAVAILABLE", response.path("error").path("code").asText());
                assertEquals(method.equals("dispatch") ? "unknown" : "none_confirmed", response.path("error").path("effects").asText());
            }
            assertEquals(List.of("prepare", "dispatch", "operation.get", "operation.cancel"), calls);
            for (var control : controls) assertEquals("CANCELLATION_REQUESTED", assertThrows(ContractException.class, control::checkpoint).code());
            assertFalse(session.verifiedWriteProfile());
        }
    }
    @Test void bridgeOutputCleanupPreservesOriginalInstallerCurrentAndDeadlineFailures() throws Exception {
        // Real processes are unnecessary for this close boundary: a controlled
        // owned stream exercises the exact production cleanup helper directly.
        for (Throwable original : List.of(
                new java.util.concurrent.ExecutionException(new ContractException("FIXTURE_INSTALL_FAILED", "합성 installer 오류")),
                new ContractException("FIXTURE_CONTEXT_STALE", "합성 현재성 오류"),
                new java.util.concurrent.TimeoutException("합성 원 기한 오류"))) {
            IOException closing = new IOException("합성 broken pipe close 오류");
            AtomicInteger closes = new AtomicInteger();
            var output = new DataOutputStream(OutputStream.nullOutputStream()) {
                @Override public void close() throws IOException { closes.incrementAndGet(); throw closing; }
            };
            assertDoesNotThrow(() -> AnonymousBridge.closeOutput(output, original));
            assertEquals(1, closes.get()); assertArrayEquals(new Throwable[] {closing}, original.getSuppressed());
        }
        IOException closing = new IOException("합성 단독 close 오류");
        var output = new DataOutputStream(OutputStream.nullOutputStream()) {
            @Override public void close() throws IOException { throw closing; }
        };
        assertSame(closing, assertThrows(IOException.class, () -> AnonymousBridge.closeOutput(output, null)));
    }

    @Test void privateApprovalBridgeAllowsBootstrapAndRejectsOtherPurposesBeforeLaunching() {
        // Existing stream cleanup fixtures cannot detect this runtime purpose
        // rejection. Exercise the exact production gate without launching a child.
        for (String purpose : List.of("numeric_calibration_normative47/1", "numeric_calibration_bootstrap/1")) {
            ObjectNode offer = ContractJson.newObject().put("purpose", purpose);
            assertTrue(AnonymousBridge.calibrationApprovalPurpose(AnonymousBridge.Mode.APPLY_APPROVAL, offer));
            assertThrows(ContractException.class,
                    () -> AnonymousBridge.calibrationApprovalPurpose(AnonymousBridge.Mode.PAIRING, offer));
        }
        for (String purpose : List.of("numeric_calibration_bootstrap/2", "numeric_calibration_other/1", "", " numeric_calibration_bootstrap/1")) {
            ObjectNode offer = ContractJson.newObject().put("purpose", purpose);
            assertThrows(ContractException.class,
                    () -> AnonymousBridge.calibrationApprovalPurpose(AnonymousBridge.Mode.APPLY_APPROVAL, offer));
        }
        ObjectNode missing = ContractJson.newObject();
        assertFalse(AnonymousBridge.calibrationApprovalPurpose(AnonymousBridge.Mode.PAIRING, missing));
        assertFalse(AnonymousBridge.calibrationApprovalPurpose(AnonymousBridge.Mode.APPLY_APPROVAL, missing));
        ObjectNode explicitNull = ContractJson.newObject().putNull("purpose");
        assertThrows(ContractException.class,
                () -> AnonymousBridge.calibrationApprovalPurpose(AnonymousBridge.Mode.APPLY_APPROVAL, explicitNull));
    }

    private static ObjectNode request(String method, String id) {
        ObjectNode request = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION).put("requestId", id)
                .put("method", method).put("deadlineAt", NOW.plusSeconds(30).toString());
        if ("inspect".equals(method)) request.put("contextId", "context-fixture-01"); else request.putNull("contextId");
        request.putObject("payload"); return request;
    }
    private static ObjectNode fixture(String name) throws IOException {
        Path source = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(source)) { return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1))); }
    }
    private static final class MutableClock extends Clock {
        private Instant now = NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
