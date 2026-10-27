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
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Existing fixtures do not cover live permission drift, cancellation, scoped handles or dedup dispatch. */
final class HostAuthorityBoundaryTest {
    private final ContractJson contracts = new ContractJson();
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-13T11:59:00Z"), ZoneOffset.UTC);

    @Test void contextAndHandlesCannotCrossSessionBindingContextTypeOrEpoch() throws IOException {
        ObjectNode context = fixture("invocation.json").withObject("context").deepCopy();
        HostSession session = session(Set.of("diagnostic.read"), false);
        session.installContext(contracts, context);
        context.put("principalRef", "untrusted-changed");
        assertEquals("principal-fixture", session.context("context-fixture-01").path("principalRef").asText());
        ObjectNode changed = session.context("context-fixture-01").put("anchor", "eyes");
        changed.put("contextDigest", ContractJson.contextDigest(changed));
        assertEquals("CONTEXT_CHANGED", assertThrows(ContractException.class, () -> session.installContext(contracts, changed)).code());
        ScopedHandles handles = new ScopedHandles();
        ObjectNode originalContext = session.context("context-fixture-01");
        ObjectNode callerContext = originalContext.deepCopy();
        String token = handles.create(session, "binding-fixture-01", callerContext, "job", "owned-job", String.class);
        callerContext.put("anchor", "eyes"); callerContext.put("contextDigest", ContractJson.contextDigest(callerContext));
        assertEquals(originalContext, session.context("context-fixture-01"));
        assertEquals("owned-job", handles.resolve(session, "binding-fixture-01", originalContext.deepCopy(), token, "job", String.class));
        ObjectNode secondContext = installSecondContext(session);
        assertEquals("HANDLE_SCOPE_MISMATCH", assertThrows(ContractException.class,
                () -> handles.resolve(session, "binding-fixture-01", secondContext, token, "job", String.class)).code());
        assertEquals("HANDLE_SCOPE_MISMATCH", assertThrows(ContractException.class,
                () -> handles.resolve(session, "binding-fixture-01", callerContext, token, "job", String.class)).code());
        assertEquals("HANDLE_SCOPE_MISMATCH", assertThrows(ContractException.class,
                () -> handles.create(session, "binding-fixture-01", callerContext, "job", "forged-job", String.class)).code());
        ObjectNode changedWithOriginalDigest = originalContext.deepCopy().put("anchor", "eyes");
        assertEquals("HANDLE_SCOPE_MISMATCH", assertThrows(ContractException.class,
                () -> handles.resolve(session, "binding-fixture-01", changedWithOriginalDigest, token, "job", String.class)).code());
        assertEquals("HANDLE_SCOPE_MISMATCH", assertThrows(ContractException.class,
                () -> handles.create(session, "binding-fixture-01", changedWithOriginalDigest, "job", "forged-job", String.class)).code());
        assertThrows(ContractException.class, () -> handles.resolve(session, "other-binding", originalContext, token, "job", String.class));
        HostSession otherSession = installed(Set.of(), false);
        assertThrows(ContractException.class, () -> handles.resolve(otherSession, "binding-fixture-01", originalContext, token, "job", String.class));
        assertThrows(ContractException.class, () -> handles.resolve(session, "binding-fixture-01", originalContext, token, "entity", String.class));
        assertThrows(ContractException.class, () -> handles.resolve(session, "binding-fixture-01", originalContext, token, "job", CharSequence.class));
        session.close();
        assertThrows(ContractException.class, () -> handles.resolve(session, "binding-fixture-01", originalContext, token, "job", String.class));
    }

    @Test void livePermissionDriftAndUnverifiedWriteProfileStopTheHandler() throws IOException {
        QueueThread queue = new QueueThread(); AtomicInteger writes = new AtomicInteger();
        ObjectNode action = action().put("effect", "write");
        HostSession session = installed(Set.of("diagnostic.read"), false);
        try (HostRuntime runtime = runtime(queue, false)) {
            register(runtime, action, (invocation, local) -> { writes.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation)); }, OptionalCallbacks.none());
            var result = runtime.dispatch(session, invocation(action)); queue.drain();
            assertEquals("failed", result.toCompletableFuture().join().status()); assertEquals(0, writes.get());
        }
        try (HostRuntime runtime = runtime(queue, true)) {
            register(runtime, action(), (invocation, local) -> { writes.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation)); }, OptionalCallbacks.none());
            var result = runtime.dispatch(installed(Set.of("diagnostic.read"), true), invocation(action())); queue.drain();
            assertEquals("failed", result.toCompletableFuture().join().status()); assertEquals(0, writes.get());
        }
    }

    @Test void cancelledQueuedInvocationDoesNotExecuteAndDedupNeverRepeatsTheWrite() throws IOException {
        QueueThread queue = new QueueThread(); AtomicInteger calls = new AtomicInteger(); ObjectNode action = action();
        HostSession session = installed(Set.of("diagnostic.read"), true);
        try (HostRuntime runtime = runtime(queue, false)) {
            register(runtime, action, (invocation, local) -> { calls.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation)); }, OptionalCallbacks.none());
            Invocation invocation = invocation(action);
            var first = runtime.dispatch(session, invocation); var duplicate = runtime.dispatch(session, invocation);
            assertFalse(runtime.cancel(session, invocation.invocationId()).toCompletableFuture().join().path("terminationConfirmed").asBoolean());
            queue.drain();
            assertEquals("failed", first.toCompletableFuture().join().status()); assertEquals("failed", duplicate.toCompletableFuture().join().status());
            assertEquals(0, calls.get());
            assertTrue(runtime.operation(session, invocation.invocationId()).path("providerCompleted").asBoolean());
            assertTrue(runtime.cancel(session, invocation.invocationId()).toCompletableFuture().join().path("terminationConfirmed").asBoolean());
            ObjectNode different = invocation.wire(); different.withObject("arguments").put("text", "different");
            different.put("argumentsDigest", ContractJson.digest(different.path("arguments")));
            assertEquals("IDEMPOTENCY_CONFLICT", assertThrows(ContractException.class, () -> runtime.dispatch(session, new Invocation(contracts, different))).code());
        }
    }

    @Test void terminalJobPollRevokesOriginalContextAndCancellationAckDoesNotProveTermination() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action().put("completion", "job").put("cancellation", "cooperative");
        HostSession session = installed(Set.of("diagnostic.read"), true);
        AtomicReference<LocalContext> original = new AtomicReference<>();
        OptionalCallbacks callbacks = new OptionalCallbacks(null,
                (handle, local) -> {
                    assertEquals("job-1", local.resolveHandle(handle, "job", String.class));
                    return CompletableFuture.completedFuture(ProviderResult.complete(contracts, ContractJson.newObject().put("text", "MMMM"), "none"));
                },
                (handle, local) -> {
                    assertEquals("job-1", local.resolveHandle(handle, "job", String.class));
                    return CompletableFuture.completedFuture(ContractJson.newObject().put("acknowledged", true));
                });
        try (HostRuntime runtime = runtime(queue, false)) {
            register(runtime, action, (invocation, local) -> {
                original.set(local); String handle = local.createHandle("job", "job-1", String.class);
                ObjectNode accepted = echo(invocation).wire().put("status", "job_accepted").put("jobHandle", handle);
                return CompletableFuture.completedFuture(new ProviderResult(contracts, accepted));
            }, callbacks);
            Invocation invocation = invocation(action); var accepted = runtime.dispatch(session, invocation); queue.drain();
            assertEquals("job_accepted", accepted.toCompletableFuture().join().status());
            var cancelled = runtime.cancel(session, invocation.invocationId()); queue.drain();
            assertFalse(cancelled.toCompletableFuture().join().path("terminationConfirmed").asBoolean());
            assertTrue(cancelled.toCompletableFuture().join().path("providerReport").path("acknowledged").asBoolean());
            var polled = runtime.poll(session, invocation.invocationId()); queue.drain();
            assertTrue(polled.toCompletableFuture().join().path("providerCompleted").asBoolean());
            assertEquals("complete", polled.toCompletableFuture().join().path("result").path("status").asText());
            assertEquals("INVOCATION_FINISHED", assertThrows(ContractException.class, () -> original.get().checkActive()).code());
        }
    }

    @Test void executionHandlesCannotCrossContextsWithinTheSameSession() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action();
        HostSession session = installed(Set.of("diagnostic.read"), false);
        ObjectNode contextA = session.context("context-fixture-01");
        ObjectNode contextB = installSecondContext(session);
        AtomicReference<String> handle = new AtomicReference<>(); AtomicInteger nativeReads = new AtomicInteger();
        try (HostRuntime runtime = runtime(queue, false)) {
            register(runtime, action, (invocation, local) -> {
                if (handle.get() == null) handle.set(local.createHandle("entity", "native-entity-a", String.class));
                assertEquals("native-entity-a", local.resolveHandle(handle.get(), "entity", String.class));
                nativeReads.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation));
            }, OptionalCallbacks.none());
            var created = runtime.dispatch(session, invocationInContext(action, contextA, "create-a")); queue.drain();
            assertEquals("complete", created.toCompletableFuture().join().status()); assertEquals(1, nativeReads.get());
            var crossed = runtime.dispatch(session, invocationInContext(action, contextB, "reuse-b")); queue.drain();
            ProviderResult rejected = crossed.toCompletableFuture().join();
            assertEquals("failed", rejected.status()); assertEquals("none", rejected.effects());
            assertEquals("HANDLE_SCOPE_MISMATCH", rejected.wire().path("diagnostics").get(0).path("code").asText());
            assertEquals(1, nativeReads.get(), "A rejected handle must not reach native access");
            var sameContext = runtime.dispatch(session, invocationInContext(action, contextA, "reuse-a")); queue.drain();
            assertEquals("complete", sameContext.toCompletableFuture().join().status()); assertEquals(2, nativeReads.get());
            assertEquals(contextA, session.context(contextA.path("contextId").asText()));
        }
    }

    @Test void acceptedJobCannotBorrowAHandleFromAnotherInstalledContext() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode action = action().put("completion", "job");
        HostSession session = installed(Set.of("diagnostic.read"), false);
        ObjectNode contextA = session.context("context-fixture-01"); ObjectNode contextB = installSecondContext(session);
        AtomicReference<String> handle = new AtomicReference<>(); AtomicInteger polls = new AtomicInteger();
        OptionalCallbacks callbacks = new OptionalCallbacks(null, (token, local) -> {
            assertEquals("native-job-a", local.resolveHandle(token, "job", String.class)); polls.incrementAndGet();
            return CompletableFuture.completedFuture(ProviderResult.complete(contracts, ContractJson.newObject().put("text", "MMMM"), "none"));
        }, null);
        try (HostRuntime runtime = runtime(queue, false)) {
            register(runtime, action, (invocation, local) -> {
                if (handle.get() == null) handle.set(local.createHandle("job", "native-job-a", String.class));
                return CompletableFuture.completedFuture(new ProviderResult(contracts,
                        echo(invocation).wire().put("status", "job_accepted").put("jobHandle", handle.get())));
            }, callbacks);
            Invocation first = invocationInContext(action, contextA, "job-a");
            var accepted = runtime.dispatch(session, first); queue.drain();
            assertEquals("job_accepted", accepted.toCompletableFuture().join().status());
            var crossed = runtime.dispatch(session, invocationInContext(action, contextB, "job-b")); queue.drain();
            ProviderResult rejected = crossed.toCompletableFuture().join();
            assertEquals("failed", rejected.status()); assertEquals("none", rejected.effects());
            assertEquals("OUTPUT_INVALID", rejected.wire().path("diagnostics").get(0).path("code").asText());
            var polled = runtime.poll(session, first.invocationId()); queue.drain();
            assertEquals("complete", polled.toCompletableFuture().join().path("result").path("status").asText());
            assertEquals(1, polls.get());
        }
    }

    private HostRuntime runtime(QueueThread queue, boolean deny) {
        return new HostRuntime(contracts, queue, new HostAuthority() {
            @Override public boolean ready() { return true; }
            @Override public ObjectNode hello() { return ContractJson.newObject(); }
            @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) {
                if (deny) throw new ContractException("PERMISSION_DENIED", "Live permission changed");
            }
            @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) { }
        }, (binding, descriptor) -> { }, CLOCK);
    }
    private void register(HostRuntime runtime, ObjectNode action, io.github.daejunnom.mmmm.sdk.ActionHandler handler,
                          OptionalCallbacks callbacks) throws IOException {
        ObjectNode provider = fixture("provider-supported.json"); provider.putArray("actions"); runtime.registerProvider(provider);
        runtime.register("binding-fixture-01", action, handler, callbacks);
    }
    private ObjectNode action() throws IOException {
        return ContractJson.object(fixture("provider-supported.json").path("actions").get(0)).deepCopy().put("planning", "unsupported");
    }
    private Invocation invocation(ObjectNode action) throws IOException {
        ObjectNode value = fixture("invocation.json"); value.put("actionDigest", ContractJson.digest(action));
        return new Invocation(contracts, value);
    }
    private Invocation invocationInContext(ObjectNode action, ObjectNode context, String suffix) throws IOException {
        ObjectNode value = invocation(action).wire();
        value.put("invocationId", "invocation-fixture-" + suffix).put("idempotencyKey", "fixture-request-" + suffix);
        value.set("context", context.deepCopy()); value.put("contextDigest", context.path("contextDigest").asText());
        return new Invocation(contracts, value);
    }
    private ObjectNode installSecondContext(HostSession session) {
        ObjectNode context = session.context("context-fixture-01").put("contextId", "context-fixture-02");
        context.withArray("origin").set(0, context.numberNode(16));
        context.put("contextDigest", ContractJson.contextDigest(context)); session.installContext(contracts, context); return context;
    }
    private ProviderResult echo(Invocation invocation) {
        return ProviderResult.complete(contracts, invocation.arguments(), "none");
    }
    private HostSession installed(Set<String> permissions, boolean profile) throws IOException {
        HostSession session = session(permissions, profile); session.installContext(contracts, fixture("invocation.json").path("context")); return session;
    }
    private static HostSession session(Set<String> permissions, boolean profile) {
        return new HostSession("principal-fixture", "epoch-fixture-01", "game-fixture-01", "server", UUID.randomUUID(), permissions, profile);
    }
    private static ObjectNode fixture(String name) throws IOException {
        Path source = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(source)) { return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1))); }
    }
    private static final class QueueThread implements GameThread {
        private final ArrayDeque<Runnable> queue = new ArrayDeque<>(); private boolean active;
        @Override public boolean isSameThread() { return active; }
        @Override public void execute(Runnable runnable) { queue.add(runnable); }
        void drain() { active = true; try { while (!queue.isEmpty()) queue.removeFirst().run(); } finally { active = false; } }
    }
}
