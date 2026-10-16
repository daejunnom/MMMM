// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.fixture.provider;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.fixture.legacy.LegacyCounterApi;
import io.github.daejunnom.mmmm.fixture.legacy.LegacyCounterException;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.Provider;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import io.github.daejunnom.mmmm.sdk.Registrar;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletionStage;

/** SDK facade for the exact counter used by the SDK-less public API and command. */
public final class FixtureProvider implements Provider {
    private static final int MAX_JOBS = 16;
    private final String authoredDigest;
    private final CounterPort counter;
    public FixtureProvider() { authoredDigest = null; counter = new NativeCounter(); }
    /** Package-private authored tests supply observations, never production source authority. */
    FixtureProvider(String authoredDigest, CounterPort counter) {
        this.authoredDigest = Objects.requireNonNull(authoredDigest); this.counter = Objects.requireNonNull(counter);
    }
    @Override public void register(Registrar registrar) {
        ContractJson contracts = new ContractJson();
        String digest = authoredDigest == null ? FixtureSourceDigest.observe(FixtureProvider.class) : authoredDigest;
        ObjectNode read = FixtureActions.read(digest), set = FixtureActions.set(digest), job = FixtureActions.job(digest);
        for (ObjectNode descriptor : new ObjectNode[] { read, set, job }) contracts.validate("ActionDescriptor", descriptor);
        // Per-registration transient host callback state. The original host
        // handle binds each entry to one binding/session/context; no journal.
        ActionSet actions = new ActionSet(contracts, digest, counter);
        registrar.action(read, (invocation, local) -> {
            actions.verify(invocation, read);
            return local.onGameThread(() -> actions.read(local));
        }, new OptionalCallbacks(actions.prepare(read), null, null, (request, local) -> {
            if (!request.actionId().equals(read.path("actionId").asText())
                    || !request.actionDigest().equals(ContractJson.digest(read))) throw pinChanged();
            return local.onGameThread(() -> actions.read(local));
        }, null));
        registrar.action(set, (invocation, local) -> {
            actions.verify(invocation, set);
            return local.onGameThread(() -> actions.set(invocation.arguments(), local));
        }, new OptionalCallbacks(actions.prepare(set), null, null));
        registrar.action(job, (invocation, local) -> {
            actions.verify(invocation, job);
            return local.onGameThread(() -> actions.job(invocation, local));
        }, new OptionalCallbacks(actions.prepare(job), actions::poll, actions::cancel));
    }

    interface Ticket {
        CompletionStage<Map<String, Object>> stage();
        Map<String, Object> observe();
    }
    interface CounterPort {
        Map<String, Object> observe(String executor, String dimension);
        int set(String executor, String dimension, int expected, int value, String fault);
        Ticket beginJob(String executor, String dimension, int expected, int value, int delayTicks, String fault);
        boolean cancel(Ticket ticket, String executor, String dimension);
    }
    private record NativeTicket(LegacyCounterApi.JobTicket actual) implements Ticket {
        @Override public CompletionStage<Map<String, Object>> stage() { return actual.stage(); }
        @Override public Map<String, Object> observe() { return actual.observe(); }
    }
    private static final class NativeCounter implements CounterPort {
        @Override public Map<String, Object> observe(String executor, String dimension) { return LegacyCounterApi.observe(executor, dimension); }
        @Override public int set(String executor, String dimension, int expected, int value, String fault) {
            return LegacyCounterApi.set(executor, dimension, expected, value, fault);
        }
        @Override public Ticket beginJob(String executor, String dimension, int expected, int value, int delayTicks, String fault) {
            return new NativeTicket(LegacyCounterApi.beginJob(executor, dimension, expected, value, delayTicks, fault));
        }
        @Override public boolean cancel(Ticket ticket, String executor, String dimension) {
            if (!(ticket instanceof NativeTicket nativeTicket)) throw pinChanged();
            return LegacyCounterApi.cancel(nativeTicket.actual(), executor, dimension);
        }
    }
    private record Scope(String executor, String dimension, String principal, String epoch, String digest) {
        static Scope current(LocalContext local, boolean write) {
            local.requireGameThread(); local.checkActive(); local.requirePermission(FixtureActions.READ_PERMISSION);
            if (write) local.requirePermission(FixtureActions.WRITE_PERMISSION);
            ObjectNode context = local.executionContext();
            if (!"game".equals(context.path("environment").path("kind").asText())
                    || !"server".equals(context.path("environment").path("side").asText())
                    || !local.sessionEpoch().equals(context.path("environment").path("sessionEpoch").asText())
                    || !local.principalRef().equals(context.path("principalRef").asText())) {
                throw new ContractException("FIXTURE_CONTEXT_REQUIRED", "Fixture requires the current actual server scope");
            }
            String executor = context.path("executorHandle").asText(), dimension = context.path("dimension").asText();
            if (executor.isEmpty() || executor.length() > 128 || dimension.isEmpty() || dimension.length() > 256) throw pinChanged();
            return new Scope(executor, dimension, local.principalRef(), local.sessionEpoch(), ContractJson.contextDigest(context));
        }
    }
    private static final class Job {
        private final Scope scope;
        private final String invocationDigest;
        private final String invocationId;
        private Ticket ticket;
        private String token;
        private volatile ProviderResult completed;
        private boolean effectRecorded;
        private boolean observing;
        private String observationFailure;
        private Throwable retainedObservationFailure;
        private Job(Scope scope, Invocation invocation) {
            this.scope = scope; invocationDigest = ContractJson.digest(invocation.wire()); invocationId = invocation.invocationId();
        }
        private synchronized void complete(ProviderResult value) { if (completed == null) completed = value; }
    }
    private static final class ActionSet {
        private final ContractJson contracts;
        private final String digest;
        private final CounterPort counter;
        private final Map<String, Job> jobs = new HashMap<>();
        private ActionSet(ContractJson contracts, String digest, CounterPort counter) { this.contracts = contracts; this.digest = digest; this.counter = counter; }
        private void verify(Invocation invocation, ObjectNode descriptor) {
            if (!invocation.actionId().equals(descriptor.path("actionId").asText())
                    || !invocation.actionDigest().equals(ContractJson.digest(descriptor))
                    || !invocation.actionContractVersion().equals(ContractJson.VERSION)
                    || !invocation.implementationDigest().equals(digest)) throw pinChanged();
            ContractJson.validateSchema(contracts.compileActionSchema(descriptor.get("inputSchema")), invocation.arguments());
        }
        private OptionalCallbacks.Prepare prepare(ObjectNode descriptor) {
            return (invocation, local) -> {
                verify(invocation, descriptor);
                return local.onGameThread(() -> {
                    Scope scope = Scope.current(local, false);
                    ObjectNode result = ContractJson.newObject().put("format", "mmmm.fixture.counter-prepare/1");
                    result.set("observation", observation(counter.observe(scope.executor(), scope.dimension())));
                    result.put("actionDigest", ContractJson.digest(descriptor)).put("implementationDigest", digest)
                            .put("invocationPerformed", false);
                    return result;
                });
            };
        }
        private ProviderResult read(LocalContext local) {
            Scope scope = Scope.current(local, false);
            Map<String, Object> observed = counter.observe(scope.executor(), scope.dimension());
            return ProviderResult.complete(contracts, value(integer(observed, "value")), "none");
        }
        private ProviderResult set(ObjectNode arguments, LocalContext local) {
            Scope scope = Scope.current(local, true);
            Map<String, Object> before = counter.observe(scope.executor(), scope.dimension());
            local.beginMutation();
            try {
                int returned = counter.set(scope.executor(), scope.dimension(), arguments.path("expected").intValue(),
                        arguments.path("value").intValue(), arguments.path("fault").asText());
                Map<String, Object> after = counter.observe(scope.executor(), scope.dimension());
                boolean recorded = record(local, before, after);
                return ProviderResult.complete(contracts, value(returned), recorded ? "recorded" : "unknown");
            } catch (RuntimeException failure) {
                String effects = "unknown";
                try { if (record(local, before, counter.observe(scope.executor(), scope.dimension()))) effects = "recorded"; }
                catch (RuntimeException observationFailure) { failure.addSuppressed(observationFailure); }
                return ProviderResult.failed(contracts, code(failure), effects);
            }
        }
        private ProviderResult job(Invocation invocation, LocalContext local) {
            Scope scope = Scope.current(local, true); ObjectNode arguments = invocation.arguments();
            for (Job existing : jobs.values()) {
                if (existing.scope.equals(scope) && existing.invocationId.equals(invocation.invocationId())) {
                    if (!existing.invocationDigest.equals(ContractJson.digest(invocation.wire()))) throw pinChanged();
                    ProviderResult observed = existing.completed; return observed == null ? accepted(existing) : observed;
                }
            }
            if (jobs.size() >= MAX_JOBS) throw new ContractException("FIXTURE_JOB_LIMIT", "Retained fixture jobs reached their finite bound");
            Map<String, Object> before = counter.observe(scope.executor(), scope.dimension());
            String id = "fixture-job-" + UUID.randomUUID(); Job entry = new Job(scope, invocation);
            entry.token = local.createHandle("job", id, String.class); jobs.put(id, entry);
            try {
                local.beginMutation();
                entry.ticket = counter.beginJob(scope.executor(), scope.dimension(), arguments.path("expected").intValue(),
                        arguments.path("value").intValue(), arguments.path("delayTicks").intValue(), arguments.path("fault").asText());
                // The actual counter changes at submission. Ticks deliver only
                // this original completion, including the late-completion fault.
                try { entry.effectRecorded = record(local, before, counter.observe(scope.executor(), scope.dimension())); }
                catch (RuntimeException observationFailure) { retainFailure(entry, observationFailure); }
                observeCompletion(entry);
                return accepted(entry);
            } catch (RuntimeException failure) {
                // A submitted ticket stays a pending actual source even if
                // the first observation or stage subscription failed. Poll may
                // observe that same stage; it never submits another mutation.
                if (entry.ticket != null) {
                    retainFailure(entry, failure); return accepted(entry);
                }
                ProviderResult result = ProviderResult.failed(contracts, code(failure), "unknown"); entry.complete(result);
                return result;
            }
        }
        private static void retainFailure(Job entry, RuntimeException failure) {
            if (entry.observationFailure == null) {
                entry.observationFailure = code(failure); entry.retainedObservationFailure = failure;
            } else if (entry.retainedObservationFailure != failure && entry.retainedObservationFailure.getSuppressed().length < 2) {
                entry.retainedObservationFailure.addSuppressed(failure);
            }
        }
        private void observeCompletion(Job entry) {
            if (entry.observing || entry.ticket == null) return;
            entry.ticket.stage().whenComplete((data, failure) -> {
                ProviderResult result;
                if (entry.observationFailure != null) {
                    if (failure != null && failure != entry.retainedObservationFailure
                            && entry.retainedObservationFailure.getSuppressed().length < 2) entry.retainedObservationFailure.addSuppressed(failure);
                    result = ProviderResult.failed(contracts, entry.observationFailure, "unknown");
                } else {
                    try { result = failure == null ? ProviderResult.complete(contracts, value(integer(data, "value")), entry.effectRecorded ? "recorded" : "unknown")
                            : ProviderResult.failed(contracts, code(failure), entry.effectRecorded ? "recorded" : "unknown"); }
                    catch (RuntimeException invalid) { result = ProviderResult.failed(contracts, "FIXTURE_JOB_OUTPUT_INVALID", "unknown"); }
                }
                entry.complete(result);
            });
            entry.observing = true;
        }
        private Job owned(String token, LocalContext local, boolean write) {
            Scope scope = Scope.current(local, write);
            String id = local.resolveHandle(token, "job", String.class); Job entry = jobs.get(id);
            if (entry == null || !token.equals(entry.token) || !scope.equals(entry.scope)) throw pinChanged();
            return entry;
        }
        private CompletionStage<ProviderResult> poll(String token, LocalContext local) {
            return local.onGameThread(() -> {
                Job entry = owned(token, local, false);
                try { observeCompletion(entry); }
                catch (RuntimeException observationFailure) { retainFailure(entry, observationFailure); }
                ProviderResult result = entry.completed; return result == null ? accepted(entry) : result;
            });
        }
        private CompletionStage<ObjectNode> cancel(String token, LocalContext local) {
            return local.onGameThread(() -> {
                Job entry = owned(token, local, true);
                boolean stopped = entry.ticket != null && counter.cancel(entry.ticket, entry.scope.executor(), entry.scope.dimension());
                return ContractJson.newObject().put("cancellationRequested", true).put("stopConfirmed", stopped)
                        .put("rollbackPerformed", false).put("completionObserved", entry.completed != null);
            });
        }
        private ProviderResult accepted(Job entry) {
            ObjectNode wire = ContractJson.newObject().put("contractVersion", ContractJson.VERSION)
                    .put("status", "job_accepted").put("effects", "unknown").put("jobHandle", entry.token);
            wire.putObject("data"); var diagnostics = wire.putArray("diagnostics"); wire.putArray("artifacts");
            if (entry.observationFailure != null) diagnostics.addObject().put("code", entry.observationFailure)
                    .put("severity", "warning").put("message", "Original fixture job remains observed after a source observation failure");
            return new ProviderResult(contracts, wire);
        }
    }
    private static boolean record(LocalContext local, Map<String, Object> before, Map<String, Object> after) {
        Object a = before.get("mutationCount"), b = after.get("mutationCount");
        if (!(a instanceof Number left) || !(b instanceof Number right) || right.longValue() <= left.longValue()) return false;
        ObjectNode effect = ContractJson.newObject().put("format", "mmmm.fixture.counter-effect/1");
        effect.set("before", observation(before)); effect.set("after", observation(after)); local.recordEffect(effect); return true;
    }
    private static ObjectNode observation(Map<String, Object> fields) {
        if (fields == null || fields.size() > 16) throw pinChanged();
        ObjectNode result = ContractJson.newObject();
        for (var field : fields.entrySet()) {
            if (field.getKey().length() > 64) throw pinChanged();
            Object value = field.getValue();
            if (value instanceof String text && text.length() <= 256) result.put(field.getKey(), text);
            else if (value instanceof Integer number) result.put(field.getKey(), number);
            else if (value instanceof Long number && number >= 0 && number <= 9_007_199_254_740_991L) result.put(field.getKey(), number);
            else if (value instanceof Boolean flag) result.put(field.getKey(), flag);
            else throw pinChanged();
        }
        return result;
    }
    private static int integer(Map<String, Object> fields, String name) {
        if (fields == null || !(fields.get(name) instanceof Integer value) || value < 0 || value > 10_000) throw pinChanged();
        return value;
    }
    private static ObjectNode value(int value) { return ContractJson.newObject().put("value", value); }
    private static String code(Throwable error) {
        Throwable cause = error;
        for (int depth = 0; depth < 8 && (cause instanceof java.util.concurrent.CompletionException
                || cause instanceof java.util.concurrent.ExecutionException) && cause.getCause() != null; depth++) cause = cause.getCause();
        if (cause instanceof ContractException contract) return contract.code();
        return cause instanceof LegacyCounterException legacy ? legacy.code() : "FIXTURE_COUNTER_FAILED";
    }
    private static ContractException pinChanged() {
        return new ContractException("FIXTURE_SCOPE_OR_PIN_CHANGED", "Fixture invocation, source, handle or current scope differs");
    }
}
