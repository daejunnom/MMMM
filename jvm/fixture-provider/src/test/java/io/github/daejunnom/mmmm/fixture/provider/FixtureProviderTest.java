// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.fixture.provider;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ActionHandler;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import io.github.daejunnom.mmmm.sdk.RegisteredActionRead;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Authored SDK callback boundary fixtures complement the legacy engine tests.
 * They run no game and cannot issue a loaded source, target or release proof.
 */
final class FixtureProviderTest {
    private static final String DIGEST = "11".repeat(32);
    private final ContractJson contracts = new ContractJson();
    private record Registration(ObjectNode descriptor, ActionHandler handler, OptionalCallbacks callbacks) { }

    @Test void registrationsDeclareOnlyBoundedCallbacksAndExactOriginalContracts() {
        Map<String, Registration> registered = register(new Counter());
        assertEquals(Set.of(FixtureActions.READ, FixtureActions.SET, FixtureActions.JOB), registered.keySet());
        registered.values().forEach(value -> contracts.validate("ActionDescriptor", value.descriptor()));
        assertNotNull(registered.get(FixtureActions.READ).callbacks().read());
        assertNotNull(registered.get(FixtureActions.JOB).callbacks().poll());
        assertNotNull(registered.get(FixtureActions.JOB).callbacks().cancel());
        assertTrue(registered.values().stream().allMatch(value -> value.callbacks().recover() == null));
        assertTrue(registered.values().stream().allMatch(value -> "declared".equals(value.descriptor().path("versionEvidence").asText())));
    }
    @Test void profilesAreExactStaticDeclarationsWithoutReceiverOrApprovalFields() {
        for (String operation : new String[] { "read", "set", "job" }) {
            ObjectNode profile = FixtureProfiles.publicJava(contracts, operation, DIGEST);
            contracts.validate("CompatibilityProfile", profile);
            assertEquals("static", profile.path("binding").path("receiver").asText());
            assertEquals("invoke_only", profile.path("binding").path("initialization").asText());
            assertFalse(profile.path("binding").has("receiverHandleType"));
            assertEquals("executorHandle", profile.path("binding").path("arguments").get(0).path("field").asText());
            assertEquals("dimension", profile.path("binding").path("arguments").get(1).path("field").asText());
            assertEquals(DIGEST, profile.path("action").path("implementationDigest").asText());
        }
        for (String operation : new String[] { "read", "set" }) contracts.validate("CompatibilityProfile", FixtureProfiles.command(contracts, operation, DIGEST));
        assertThrows(ContractException.class, () -> FixtureProfiles.command(contracts, "job", DIGEST));
        assertThrows(ContractException.class, () -> FixtureProfiles.publicJava(contracts, "read", "not-a-source-pin"));
    }
    @Test void readAndWriteUseTheGuardedQueueAndRecordActualPortObservations() throws IOException {
        Counter counter = new Counter(); var registered = register(counter); Context context = context();
        Registration read = registered.get(FixtureActions.READ);
        ObjectNode request = ContractJson.newObject().put("contextId", context.wire.path("contextId").asText())
                .put("bindingId", "binding-fixture-01").put("actionId", FixtureActions.READ)
                .put("actionDigest", ContractJson.digest(read.descriptor())); request.putObject("arguments");
        var reading = read.callbacks().read().read(new RegisteredActionRead(contracts, request), context);
        assertFalse(reading.toCompletableFuture().isDone()); assertEquals(0, counter.reads); context.drain();
        assertEquals(0, reading.toCompletableFuture().join().data().path("value").asInt());
        Registration set = registered.get(FixtureActions.SET); var writing = set.handler().execute(invocation(set, write(0, 7, "none")), context);
        assertEquals(0, counter.writes); context.drain(); ProviderResult result = writing.toCompletableFuture().join();
        assertEquals(7, result.data().path("value").asInt()); assertEquals("recorded", result.effects());
        assertEquals(1, counter.writes); assertEquals(1, context.effects); assertEquals(1, context.mutationBoundaries);
    }
    @Test void sourcePinAndSchemaFailurePrecedeAnyTargetCall() throws IOException {
        Counter counter = new Counter(); var registered = register(counter); Registration set = registered.get(FixtureActions.SET); Context context = context();
        ObjectNode raw = invocation(set, write(0, 7, "none")).wire().put("implementationDigest", "22".repeat(32));
        assertThrows(ContractException.class, () -> set.handler().execute(new Invocation(contracts, raw), context));
        ObjectNode invalid = write(0, 7, "none").put("expected", 0.5);
        assertThrows(ContractException.class, () -> set.handler().execute(invocation(set, invalid), context));
        assertEquals(0, counter.reads); assertEquals(0, counter.writes); assertEquals(0, context.mutationBoundaries);
    }
    @Test void permissionAndSideAreCheckedBeforeMutation() throws IOException {
        Counter counter = new Counter(); Registration set = register(counter).get(FixtureActions.SET);
        Context readOnly = context(); readOnly.permissions = Set.of(FixtureActions.READ_PERMISSION);
        var forbidden = set.handler().execute(invocation(set, write(0, 7, "none")), readOnly); readOnly.drain();
        assertThrows(CompletionException.class, () -> forbidden.toCompletableFuture().join());
        Context client = context(); client.wire.withObject("environment").put("side", "client"); client.stamp();
        var wrongSide = set.handler().execute(invocation(set, write(0, 7, "none"), client.wire), client); client.drain();
        assertThrows(CompletionException.class, () -> wrongSide.toCompletableFuture().join());
        assertEquals(0, counter.writes); assertEquals(0, readOnly.mutationBoundaries); assertEquals(0, client.mutationBoundaries);
    }
    @Test void responseLossPreservesTheActualChangeAndKnownObservation() throws IOException {
        Counter counter = new Counter(); Registration set = register(counter).get(FixtureActions.SET); Context context = context();
        var lost = set.handler().execute(invocation(set, write(0, 9, "lost_response")), context); context.drain();
        ProviderResult result = lost.toCompletableFuture().join();
        assertEquals("failed", result.status()); assertEquals("recorded", result.effects()); assertEquals(9, counter.value);
        assertEquals(1, counter.writes); assertEquals(1, context.effects);
        assertEquals("COUNTER_RESPONSE_LOST", result.wire().path("diagnostics").get(0).path("code").asText());
    }
    @Test void duplicateAndPollNeverRestartTheOriginalJob() throws IOException {
        Counter counter = new Counter(); Registration job = register(counter).get(FixtureActions.JOB); Context context = context();
        Invocation original = invocation(job, write(0, 4, "none").put("delayTicks", 2));
        var starting = job.handler().execute(original, context); context.drain(); ProviderResult accepted = starting.toCompletableFuture().join();
        assertEquals("job_accepted", accepted.status()); assertEquals("job", context.lastHandleType);
        assertEquals(String.class, context.lastHandleClass); assertEquals(1, counter.jobs); assertEquals(1, counter.writes);
        var duplicate = job.handler().execute(original, context); context.drain(); assertEquals(accepted.jobHandle(), duplicate.toCompletableFuture().join().jobHandle());
        var pending = job.callbacks().poll().poll(accepted.jobHandle(), context); context.drain(); assertEquals("job_accepted", pending.toCompletableFuture().join().status());
        counter.ticket.complete(); var finished = job.callbacks().poll().poll(accepted.jobHandle(), context); context.drain();
        assertEquals(4, finished.toCompletableFuture().join().data().path("value").asInt()); assertEquals(1, counter.jobs); assertEquals(1, counter.writes);
    }
    @Test void changedScopeCannotUseTheOriginalHostHandle() throws IOException {
        Counter counter = new Counter(); Registration job = register(counter).get(FixtureActions.JOB); Context context = context();
        var start = job.handler().execute(invocation(job, write(0, 4, "none").put("delayTicks", 2)), context); context.drain(); String token = start.toCompletableFuture().join().jobHandle();
        context.wire.withObject("environment").put("sessionEpoch", "epoch-different"); context.stamp();
        var poll = job.callbacks().poll().poll(token, context); context.drain();
        assertThrows(CompletionException.class, () -> poll.toCompletableFuture().join()); assertEquals(1, counter.jobs); assertEquals(1, counter.writes);
    }
    @Test void lateCompletionAfterUnconfirmedCancelDoesNotWriteAgain() throws IOException {
        Counter counter = new Counter(); Registration job = register(counter).get(FixtureActions.JOB); Context context = context();
        var start = job.handler().execute(invocation(job, write(0, 4, "late_completion").put("delayTicks", 2)), context); context.drain(); String token = start.toCompletableFuture().join().jobHandle();
        var cancel = job.callbacks().cancel().cancel(token, context); context.drain(); ObjectNode report = cancel.toCompletableFuture().join();
        assertFalse(report.path("stopConfirmed").asBoolean()); assertFalse(report.path("rollbackPerformed").asBoolean());
        var pending = job.callbacks().poll().poll(token, context); context.drain(); assertEquals("job_accepted", pending.toCompletableFuture().join().status());
        counter.ticket.complete(); var complete = job.callbacks().poll().poll(token, context); context.drain();
        assertEquals("complete", complete.toCompletableFuture().join().status()); assertEquals(4, counter.value); assertEquals(1, counter.writes);
    }
    @Test void failedBeforeObservationDoesNotReserveAPhantomJob() throws IOException {
        Counter counter = new Counter(); counter.failObservation = true; Registration job = register(counter).get(FixtureActions.JOB); Context context = context();
        Invocation original = invocation(job, write(0, 4, "none").put("delayTicks", 2));
        var failed = job.handler().execute(original, context); context.drain(); assertThrows(CompletionException.class, () -> failed.toCompletableFuture().join());
        assertEquals(0, context.handles.size()); assertEquals(0, counter.jobs);
        counter.failObservation = false; var retried = job.handler().execute(original, context); context.drain();
        assertEquals("job_accepted", retried.toCompletableFuture().join().status()); assertEquals(1, counter.jobs);
    }
    @Test void postSubmissionObservationFailureRetainsTheSamePendingStage() throws IOException {
        Counter counter = new Counter(); counter.failAfterSubmit = true; Registration job = register(counter).get(FixtureActions.JOB); Context context = context();
        var start = job.handler().execute(invocation(job, write(0, 4, "none").put("delayTicks", 2)), context); context.drain();
        ProviderResult accepted = start.toCompletableFuture().join(); assertEquals("job_accepted", accepted.status());
        assertEquals("EXECUTOR_DISCONNECTED", accepted.wire().path("diagnostics").get(0).path("code").asText());
        var pending = job.callbacks().poll().poll(accepted.jobHandle(), context); context.drain(); assertEquals("job_accepted", pending.toCompletableFuture().join().status());
        counter.ticket.complete(); var finalResult = job.callbacks().poll().poll(accepted.jobHandle(), context); context.drain();
        ProviderResult observed = finalResult.toCompletableFuture().join(); assertEquals("failed", observed.status());
        assertEquals("EXECUTOR_DISCONNECTED", observed.wire().path("diagnostics").get(0).path("code").asText());
        assertEquals("unknown", observed.effects()); assertEquals(4, counter.value); assertEquals(1, counter.jobs); assertEquals(1, counter.writes);
    }
    private Map<String, Registration> register(Counter counter) {
        Map<String, Registration> registrations = new HashMap<>();
        new FixtureProvider(DIGEST, counter).register((descriptor, handler, callbacks) -> {
            contracts.validate("ActionDescriptor", descriptor); ObjectNode snapshot = ContractJson.object(descriptor).deepCopy();
            assertNull(registrations.put(snapshot.path("actionId").asText(), new Registration(snapshot, handler, callbacks)));
        }); return registrations;
    }
    private Context context() throws IOException { return new Context(example("execution-context.json")); }
    private Invocation invocation(Registration registration, ObjectNode arguments) throws IOException {
        return invocation(registration, arguments, example("execution-context.json"));
    }
    private Invocation invocation(Registration registration, ObjectNode arguments, ObjectNode context) throws IOException {
        ObjectNode raw = example("invocation.json").put("actionId", registration.descriptor().path("actionId").asText())
                .put("actionDigest", ContractJson.digest(registration.descriptor())).put("implementationDigest", DIGEST);
        raw.set("arguments", arguments); raw.put("argumentsDigest", ContractJson.digest(arguments));
        raw.set("context", context.deepCopy()); raw.put("contextDigest", ContractJson.contextDigest(context)); return new Invocation(contracts, raw);
    }
    private static ObjectNode example(String file) throws IOException {
        return ContractJson.object(ContractJson.parse(Files.readAllBytes(Path.of(System.getProperty("mmmm.checkout"), "examples", file))));
    }
    private static ObjectNode write(int expected, int value, String fault) { return ContractJson.newObject().put("expected", expected).put("value", value).put("fault", fault); }
    private static final class Counter implements FixtureProvider.CounterPort {
        private int value, reads, writes, jobs; private boolean failObservation, failAfterSubmit; private Ticket ticket;
        @Override public Map<String, Object> observe(String executor, String dimension) {
            if (failObservation) throw new ContractException("EXECUTOR_DISCONNECTED", "Authored observation failure"); reads++;
            return Map.of("value", value, "revision", (long) writes, "mutationCount", (long) writes);
        }
        @Override public int set(String executor, String dimension, int expected, int next, String fault) {
            assertEquals(value, expected); value = next; writes++;
            if ("lost_response".equals(fault)) throw new ContractException("COUNTER_RESPONSE_LOST", "Authored response loss after mutation"); return value;
        }
        @Override public FixtureProvider.Ticket beginJob(String executor, String dimension, int expected, int next, int delay, String fault) {
            set(executor, dimension, expected, next, "none"); jobs++; ticket = new Ticket(next, "late_completion".equals(fault));
            if (failAfterSubmit) failObservation = true; return ticket;
        }
        @Override public boolean cancel(FixtureProvider.Ticket actual, String executor, String dimension) {
            assertSame(ticket, actual); if (ticket.late) return false;
            ticket.future.completeExceptionally(new ContractException("COUNTER_JOB_CANCELLED", "Authored completion cancellation")); return true;
        }
    }
    private static final class Ticket implements FixtureProvider.Ticket {
        private final int value; private final boolean late; private final CompletableFuture<Map<String, Object>> future = new CompletableFuture<>();
        private Ticket(int value, boolean late) { this.value = value; this.late = late; }
        @Override public CompletionStage<Map<String, Object>> stage() { return future.minimalCompletionStage(); }
        @Override public Map<String, Object> observe() { return Map.of("value", value); }
        private void complete() { future.complete(Map.of("value", value)); }
    }
    private static final class Context implements LocalContext {
        private final ObjectNode wire; private final Queue<Runnable> queue = new ArrayDeque<>();
        private final Map<String, Object> handles = new HashMap<>();
        private Set<String> permissions = Set.of(FixtureActions.READ_PERMISSION, FixtureActions.WRITE_PERMISSION);
        private boolean active; private int effects, mutationBoundaries; private String lastHandleType; private Class<?> lastHandleClass;
        private Context(ObjectNode wire) { this.wire = wire.deepCopy(); stamp(); }
        private void stamp() { wire.put("contextDigest", ContractJson.contextDigest(wire)); }
        @Override public String principalRef() { return wire.path("principalRef").asText(); }
        @Override public String sessionEpoch() { return wire.path("environment").path("sessionEpoch").asText(); }
        @Override public ObjectNode executionContext() { return wire.deepCopy(); }
        @Override public boolean cancellationRequested() { return false; }
        @Override public void requirePermission(String permission) { if (!permissions.contains(permission)) throw new ContractException("PERMISSION_DENIED", "Authored permission rejection"); }
        @Override public void requireGameThread() { if (!active) throw new ContractException("WRONG_THREAD", "Authored queue required"); }
        @Override public void checkActive() { requireGameThread(); }
        @Override public <T> CompletionStage<T> onGameThread(Supplier<T> callback) {
            CompletableFuture<T> future = new CompletableFuture<>(); queue.add(() -> { active = true;
                try { future.complete(callback.get()); } catch (RuntimeException failure) { future.completeExceptionally(failure); }
                finally { active = false; } }); return future.minimalCompletionStage();
        }
        private void drain() { while (!queue.isEmpty()) queue.remove().run(); }
        @Override public <T> String createHandle(String type, T target, Class<T> exactClass) {
            requireGameThread(); lastHandleType = type; lastHandleClass = exactClass; String id = "handle-" + handles.size(); handles.put(id, target); return id;
        }
        @Override public <T> T resolveHandle(String token, String type, Class<T> exactClass) { requireGameThread(); return exactClass.cast(handles.get(token)); }
        @Override public void recordEffect(ObjectNode effect) { requireGameThread(); assertTrue(mutationBoundaries > 0); effects++; }
        @Override public void beginMutation() { requireGameThread(); mutationBoundaries++; }
    }
}
