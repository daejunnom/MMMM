package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import io.github.daejunnom.mmmm.sdk.RegisteredActionRead;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 원본 invocation 예시는 FN33의 별도 읽기 콜백과 변이·수명·용량 경계를 다루지 않는다. */
final class RegisteredReadBoundaryTest {
    private static final Instant NOW = Instant.parse("2026-10-13T11:59:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final Instant DEADLINE = NOW.plusSeconds(10);
    private final ContractJson contracts = new ContractJson();

    @Test
    void registeredReadInvokesOnlyItsReadCallbackAndCreatesNoInvocationRecord() throws IOException {
        QueueThread queue = new QueueThread();
        LiveAuthority authority = new LiveAuthority();
        AtomicInteger dispatchCalls = new AtomicInteger();
        AtomicInteger readCalls = new AtomicInteger();
        AtomicReference<LocalContext> captured = new AtomicReference<>();
        ObjectNode action = action();
        HostSession session = installed(Set.of("diagnostic.read"));
        ObjectNode source = requestWire(action);
        RegisteredActionRead request = new RegisteredActionRead(contracts, source);
        source.withObject("arguments").put("text", "changed after snapshot");
        request.arguments().put("text", "changed accessor copy");
        request.wire().put("contextId", "other-context");

        try (HostRuntime runtime = runtime(queue, authority)) {
            register(runtime, action, dispatchCalls, (value, local) -> {
                readCalls.incrementAndGet(); captured.set(local); local.requireGameThread();
                assertEquals("MMMM", value.arguments().path("text").asText());
                assertEquals("principal-fixture", local.principalRef());
                assertEquals("epoch-fixture-01", local.sessionEpoch());
                return CompletableFuture.completedFuture(echo(value));
            });
            var result = runtime.registeredRead(session, request, DEADLINE);
            assertFalse(result.toCompletableFuture().isDone());
            assertEquals(0, readCalls.get());
            queue.drain();
            assertEquals("complete", result.toCompletableFuture().join().status());
            assertEquals("none", result.toCompletableFuture().join().effects());
            assertEquals(1, readCalls.get());
            assertEquals(0, dispatchCalls.get());
            assertEquals("INVOCATION_UNKNOWN", assertThrows(ContractException.class,
                    () -> runtime.operation(session, "invocation-fixture-01")).code());
            assertEquals("INVOCATION_FINISHED", assertThrows(ContractException.class,
                    () -> captured.get().checkActive()).code());
            assertFalse(authority.lastWrite.get());
            assertEquals(Set.of("diagnostic.read"), authority.lastPermissions.get());
        }
    }

    @Test
    void missingReadCallbackCannotFallBackToDispatchOrPrepare() throws IOException {
        QueueThread queue = new QueueThread();
        AtomicInteger dispatchCalls = new AtomicInteger();
        AtomicInteger prepareCalls = new AtomicInteger();
        ObjectNode action = action().put("planning", "pure");
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            ObjectNode provider = provider(); runtime.registerProvider(provider);
            runtime.register("binding-fixture-01", action, (value, local) -> {
                dispatchCalls.incrementAndGet(); return CompletableFuture.completedFuture(
                        ProviderResult.complete(contracts, value.arguments(), "none"));
            }, new OptionalCallbacks((value, local) -> {
                prepareCalls.incrementAndGet(); return CompletableFuture.completedFuture(ContractJson.newObject());
            }, null, null));
            assertEquals("READ_UNSUPPORTED", assertThrows(ContractException.class,
                    () -> runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE)).code());
            queue.drain();
            assertEquals(0, dispatchCalls.get()); assertEquals(0, prepareCalls.get());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"write", "unknown"})
    void registeredReadRejectsAnyNonReadEffectBeforeQueueing(String effect) throws IOException {
        QueueThread queue = new QueueThread(); AtomicInteger reads = new AtomicInteger();
        ObjectNode action = action().put("effect", effect);
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet(); return CompletableFuture.completedFuture(echo(value));
            });
            assertEquals("EFFECT_MISMATCH", assertThrows(ContractException.class,
                    () -> runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE)).code());
            queue.drain(); assertEquals(0, reads.get());
        }
    }

    @Test
    void exactActionContextAndBindingPinsCannotBeSubstituted() throws IOException {
        QueueThread queue = new QueueThread(); AtomicInteger reads = new AtomicInteger();
        ObjectNode action = action(); HostSession session = installed(Set.of("diagnostic.read"));
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet(); return CompletableFuture.completedFuture(echo(value));
            });
            for (String field : List.of("contextId", "bindingId", "actionId", "actionDigest")) {
                ObjectNode changed = requestWire(action);
                changed.put(field, switch (field) {
                    case "actionDigest" -> "0".repeat(64);
                    case "actionId" -> "fixture:unregistered";
                    default -> "unregistered-fixture";
                });
                RegisteredActionRead substituted = new RegisteredActionRead(contracts, changed);
                assertThrows(ContractException.class, () -> runtime.registeredRead(session, substituted, DEADLINE));
            }
            queue.drain(); assertEquals(0, reads.get());
        }
    }

    @Test
    void argumentsAndHostSideAreCheckedBeforeTheReadCallback() throws IOException {
        QueueThread queue = new QueueThread(); AtomicInteger reads = new AtomicInteger();
        ObjectNode action = action();
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet(); return CompletableFuture.completedFuture(echo(value));
            });
            ObjectNode unknownArgument = requestWire(action);
            unknownArgument.withObject("arguments").put("write", true);
            assertThrows(ContractException.class, () -> runtime.registeredRead(installed(Set.of("diagnostic.read")),
                    new RegisteredActionRead(contracts, unknownArgument), DEADLINE));
        }
        ObjectNode clientAction = action().put("side", "client");
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, clientAction, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet(); return CompletableFuture.completedFuture(echo(value));
            });
            assertEquals("INVOCATION_PIN_MISMATCH", assertThrows(ContractException.class,
                    () -> runtime.registeredRead(installed(Set.of("diagnostic.read")), request(clientAction), DEADLINE)).code());
            queue.drain(); assertEquals(0, reads.get());
        }
    }

    @Test
    void livePermissionDriftBeforeGameThreadEntryStopsTheReadCallback() throws IOException {
        QueueThread queue = new QueueThread(); LiveAuthority authority = new LiveAuthority();
        AtomicInteger reads = new AtomicInteger(); ObjectNode action = action();
        try (HostRuntime runtime = runtime(queue, authority)) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet(); return CompletableFuture.completedFuture(echo(value));
            });
            var result = runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE);
            authority.denied.set(true); queue.drain();
            assertEquals("PERMISSION_DENIED", failure(result).code());
            assertEquals(0, reads.get());
        }
    }

    @Test
    void missingSessionPermissionAndClosedSessionStopTheReadCallback() throws IOException {
        QueueThread queue = new QueueThread(); AtomicInteger reads = new AtomicInteger(); ObjectNode action = action();
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet(); return CompletableFuture.completedFuture(echo(value));
            });
            var denied = runtime.registeredRead(installed(Set.of()), request(action), DEADLINE);
            queue.drain(); assertEquals("PERMISSION_DENIED", failure(denied).code());
            HostSession session = installed(Set.of("diagnostic.read"));
            var closed = runtime.registeredRead(session, request(action), DEADLINE);
            session.close(); queue.drain(); assertEquals("SESSION_EXPIRED", failure(closed).code());
            assertEquals(0, reads.get());
        }
    }

    @Test
    void readContextsRejectMutationAndAreRevokedAfterTerminalCompletion() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action();
        AtomicReference<LocalContext> captured = new AtomicReference<>();
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                captured.set(local);
                assertEquals("EFFECT_NOT_DECLARED", assertThrows(ContractException.class, local::beginMutation).code());
                assertEquals("EFFECT_NOT_DECLARED", assertThrows(ContractException.class,
                        () -> local.recordEffect(ContractJson.newObject().put("effect", "fabricated"))).code());
                return CompletableFuture.completedFuture(echo(value));
            });
            var result = runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE);
            queue.drain(); assertEquals("none", result.toCompletableFuture().join().effects());
            assertNotNull(captured.get());
            assertEquals("INVOCATION_FINISHED", assertThrows(ContractException.class, captured.get()::checkActive).code());
            AtomicInteger lateAccess = new AtomicInteger();
            var late = captured.get().onGameThread(lateAccess::incrementAndGet);
            queue.drain(); assertEquals("INVOCATION_FINISHED", failure(late).code());
            assertEquals(0, lateAccess.get());
        }
    }

    @Test
    void eachQueuedNativeReadRechecksCurrentAuthority() throws IOException {
        QueueThread queue = new QueueThread(); LiveAuthority authority = new LiveAuthority();
        ObjectNode action = action(); AtomicReference<LocalContext> captured = new AtomicReference<>();
        CompletableFuture<ProviderResult> pending = new CompletableFuture<>();
        try (HostRuntime runtime = runtime(queue, authority)) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                captured.set(local); return pending;
            });
            var result = runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE);
            queue.drain(); assertFalse(result.toCompletableFuture().isDone());
            AtomicInteger nativeReads = new AtomicInteger();
            var nativeResult = captured.get().onGameThread(nativeReads::incrementAndGet);
            authority.denied.set(true); queue.drain();
            assertEquals("PERMISSION_DENIED", failure(nativeResult).code());
            assertEquals(0, nativeReads.get());
            pending.completeExceptionally(new ContractException("PERMISSION_DENIED", "Live read was denied"));
            assertEquals("PERMISSION_DENIED", failure(result).code());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"job", "recorded", "unknown", "invalid-output"})
    void readResultsCannotCreateJobsReportMutationOrBypassOutputSchema(String kind) throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action();
        AtomicReference<LocalContext> captured = new AtomicReference<>();
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                captured.set(local);
                ProviderResult result = switch (kind) {
                    case "job" -> new ProviderResult(contracts, echo(value).wire()
                            .put("status", "job_accepted").put("jobHandle", "unowned-job"));
                    case "invalid-output" -> ProviderResult.complete(contracts, ContractJson.newObject().put("other", true), "none");
                    default -> ProviderResult.complete(contracts, value.arguments(), kind);
                };
                return CompletableFuture.completedFuture(result);
            });
            var result = runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE);
            queue.drain();
            ContractException failure = failure(result);
            assertTrue(Set.of("OUTPUT_INVALID", "CONTRACT_INVALID").contains(failure.code()));
            assertEquals("INVOCATION_FINISHED", assertThrows(ContractException.class, captured.get()::checkActive).code());
        }
    }

    @Test
    void readRequestAndResultByteLimitsDoNotDependOnARestrictiveActionSchema() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action();
        action.set("inputSchema", ContractJson.newObject()); action.set("outputSchema", ContractJson.newObject());
        AtomicInteger reads = new AtomicInteger();
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet();
                ObjectNode oversized = ContractJson.newObject().put("payload", "x".repeat(HostRuntime.MAX_RESULT_BYTES));
                return CompletableFuture.completedFuture(ProviderResult.complete(contracts, oversized, "none"));
            });
            ObjectNode oversizedRequest = requestWire(action);
            oversizedRequest.withObject("arguments").put("payload", "x".repeat(HostRuntime.MAX_RESULT_BYTES));
            assertEquals("INPUT_LIMIT", assertThrows(ContractException.class,
                    () -> runtime.registeredRead(installed(Set.of("diagnostic.read")),
                            new RegisteredActionRead(contracts, oversizedRequest), DEADLINE)).code());
            queue.drain(); assertEquals(0, reads.get());
            var result = runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE);
            queue.drain(); assertEquals("OUTPUT_LIMIT", failure(result).code());
            assertEquals(1, reads.get());
        }
    }

    @Test
    void providerFailureRemainsAReadFailureWithoutClaimingMutationOrSchemaSuccess() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action();
        AtomicReference<LocalContext> captured = new AtomicReference<>();
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                captured.set(local); return CompletableFuture.completedFuture(
                        ProviderResult.failed(contracts, "READ_TARGET_UNAVAILABLE", "none"));
            });
            var result = runtime.registeredRead(installed(Set.of("diagnostic.read")), request(action), DEADLINE);
            queue.drain(); ProviderResult failed = result.toCompletableFuture().join();
            assertEquals("failed", failed.status()); assertEquals("none", failed.effects());
            assertEquals("READ_TARGET_UNAVAILABLE", failed.wire().path("diagnostics").get(0).path("code").asText());
            assertEquals("INVOCATION_FINISHED", assertThrows(ContractException.class, captured.get()::checkActive).code());
        }
    }

    @Test
    void expiredReadDoesNotQueueAndConcurrentReadLimitIsReleasedOnCompletion() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action();
        List<CompletableFuture<ProviderResult>> pending = new ArrayList<>();
        List<CompletionStage<ProviderResult>> requests = new ArrayList<>();
        AtomicInteger reads = new AtomicInteger();
        HostSession session = installed(Set.of("diagnostic.read"));
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, new AtomicInteger(), (value, local) -> {
                reads.incrementAndGet(); CompletableFuture<ProviderResult> result = new CompletableFuture<>();
                pending.add(result); return result;
            });
            assertEquals("DEADLINE_EXCEEDED", assertThrows(ContractException.class,
                    () -> runtime.registeredRead(session, request(action), NOW)).code());
            for (int index = 0; index < 32; index++) requests.add(runtime.registeredRead(session, request(action), DEADLINE));
            assertEquals("HOST_READ_LIMIT", assertThrows(ContractException.class,
                    () -> runtime.registeredRead(session, request(action), DEADLINE)).code());
            queue.drain(); assertEquals(32, reads.get());
            ProviderResult completed = echo(request(action));
            pending.forEach(value -> value.complete(completed));
            requests.forEach(value -> assertEquals("complete", value.toCompletableFuture().join().status()));
            var next = runtime.registeredRead(session, request(action), DEADLINE);
            queue.drain(); pending.get(32).complete(completed);
            assertEquals("complete", next.toCompletableFuture().join().status());
            assertEquals("INVOCATION_UNKNOWN", assertThrows(ContractException.class,
                    () -> runtime.operation(session, "invocation-fixture-01")).code());
        }
    }

    @Test
    void readHandlesRemainBoundToTheirOriginalInstalledContextWithinOneSession() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action(); AtomicInteger dispatchCalls = new AtomicInteger();
        HostSession session = installed(Set.of("diagnostic.read"));
        ObjectNode contextA = session.context("context-fixture-01");
        ObjectNode contextB = contextA.deepCopy().put("contextId", "context-fixture-02");
        contextB.withArray("origin").set(0, contextB.numberNode(16));
        contextB.put("contextDigest", ContractJson.contextDigest(contextB)); session.installContext(contracts, contextB);
        AtomicReference<String> handle = new AtomicReference<>(); AtomicInteger nativeReads = new AtomicInteger();
        try (HostRuntime runtime = runtime(queue, new LiveAuthority())) {
            register(runtime, action, dispatchCalls, (value, local) -> {
                if (handle.get() == null) handle.set(local.createHandle("entity", "native-read-entity-a", String.class));
                assertEquals("native-read-entity-a", local.resolveHandle(handle.get(), "entity", String.class));
                nativeReads.incrementAndGet(); return CompletableFuture.completedFuture(echo(value));
            });
            var created = runtime.registeredRead(session, request(action), DEADLINE); queue.drain();
            assertEquals("complete", created.toCompletableFuture().join().status()); assertEquals(1, nativeReads.get());
            ObjectNode crossWire = requestWire(action).put("contextId", contextB.path("contextId").asText());
            var crossed = runtime.registeredRead(session, new RegisteredActionRead(contracts, crossWire), DEADLINE); queue.drain();
            assertEquals("HANDLE_SCOPE_MISMATCH", failure(crossed).code());
            assertEquals(1, nativeReads.get(), "Rejected context must not reach native access");
            var original = runtime.registeredRead(session, request(action), DEADLINE); queue.drain();
            assertEquals("complete", original.toCompletableFuture().join().status()); assertEquals(2, nativeReads.get());
            assertEquals(0, dispatchCalls.get());
            assertEquals(contextA, session.context(contextA.path("contextId").asText()));
        }
    }

    private HostRuntime runtime(QueueThread queue, LiveAuthority authority) {
        return new HostRuntime(contracts, queue, authority, (binding, descriptor) -> { }, CLOCK);
    }

    private void register(HostRuntime runtime, ObjectNode action, AtomicInteger dispatchCalls,
                          OptionalCallbacks.Read read) throws IOException {
        runtime.registerProvider(provider());
        runtime.register("binding-fixture-01", action, (value, local) -> {
            dispatchCalls.incrementAndGet(); return CompletableFuture.completedFuture(
                    ProviderResult.complete(contracts, value.arguments(), "none"));
        }, new OptionalCallbacks(null, null, null, read));
    }

    private ObjectNode provider() throws IOException {
        ObjectNode provider = fixture("provider-supported.json"); provider.putArray("actions"); return provider;
    }

    private ObjectNode action() throws IOException {
        return ContractJson.object(fixture("provider-supported.json").path("actions").get(0))
                .deepCopy().put("planning", "unsupported");
    }

    private RegisteredActionRead request(ObjectNode action) {
        return new RegisteredActionRead(contracts, requestWire(action));
    }

    private static ObjectNode requestWire(ObjectNode action) {
        ObjectNode request = ContractJson.newObject().put("contextId", "context-fixture-01")
                .put("bindingId", "binding-fixture-01").put("actionId", action.path("actionId").asText())
                .put("actionDigest", ContractJson.digest(action));
        request.putObject("arguments").put("text", "MMMM"); return request;
    }

    private ProviderResult echo(RegisteredActionRead request) {
        return ProviderResult.complete(contracts, request.arguments(), "none");
    }

    private HostSession installed(Set<String> permissions) throws IOException {
        HostSession session = new HostSession("principal-fixture", "epoch-fixture-01", "game-fixture-01", "server",
                UUID.randomUUID(), permissions, false);
        session.installContext(contracts, fixture("invocation.json").path("context")); return session;
    }

    private static ObjectNode fixture(String name) throws IOException {
        Path source = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(source)) {
            return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1)));
        }
    }

    private static ContractException failure(CompletionStage<?> result) {
        CompletionException failure = assertThrows(CompletionException.class, () -> result.toCompletableFuture().join());
        Throwable cause = failure.getCause();
        while (cause instanceof CompletionException && cause.getCause() != null) cause = cause.getCause();
        assertTrue(cause instanceof ContractException, "Expected a bounded host contract failure");
        return (ContractException) cause;
    }

    private static final class LiveAuthority implements HostAuthority {
        private final AtomicBoolean denied = new AtomicBoolean();
        private final AtomicBoolean lastWrite = new AtomicBoolean();
        private final AtomicReference<Set<String>> lastPermissions = new AtomicReference<>();
        @Override public boolean ready() { return true; }
        @Override public ObjectNode hello() { return ContractJson.newObject(); }
        @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) {
            lastWrite.set(write); lastPermissions.set(permissions);
            if (denied.get()) throw new ContractException("PERMISSION_DENIED", "Live permission changed");
        }
        @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) { }
    }

    private static final class QueueThread implements GameThread {
        private final ArrayDeque<Runnable> queue = new ArrayDeque<>();
        private boolean active;
        @Override public boolean isSameThread() { return active; }
        @Override public void execute(Runnable runnable) { queue.add(runnable); }
        void drain() {
            active = true;
            try { while (!queue.isEmpty()) queue.removeFirst().run(); }
            finally { active = false; }
        }
    }
}
