package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/** One closed HostRequest dispatch table. Generic JSON payload does not enable arbitrary methods. */
public final class HostDispatcher {
    @FunctionalInterface public interface Inspection {
        CompletionStage<ObjectNode> inspect(HostSession session, ObjectNode context, ObjectNode payload, InspectionControl control);
    }
    /** 원래 요청의 기한과 해당 응답의 종료만 전달하며 별도 실행 권한을 주지 않는다. */
    public static final class InspectionControl {
        private final Clock clock;
        private final Instant deadline;
        private final long startedNanos;
        private final long budgetNanos;
        private final LongSupplier monotonic;
        private final AtomicBoolean stopped = new AtomicBoolean();
        private final AtomicBoolean stopHookRegistered = new AtomicBoolean();
        private final AtomicReference<Runnable> stopHook = new AtomicReference<>();
        InspectionControl(Clock clock, Instant deadline, Instant admittedAt, long startedNanos, LongSupplier monotonic) {
            this.clock = clock; this.deadline = deadline; this.startedNanos = startedNanos; this.monotonic = monotonic;
            this.budgetNanos = Duration.between(admittedAt, deadline).toNanos();
        }
        public Instant deadlineAt() { return deadline; }
        public void checkpoint() {
            if (stopped.get()) throw new ContractException("CANCELLATION_REQUESTED", "Inspection response has ended");
            if (Thread.currentThread().isInterrupted()) throw new ContractException("HOST_INTERRUPTED", "Inspection was interrupted");
            if (!clock.instant().isBefore(deadline) || monotonic.getAsLong() - startedNanos >= budgetNanos) {
                throw new ContractException("DEADLINE_EXCEEDED", "Original inspection deadline elapsed");
            }
        }
        public long remainingMillis() {
            checkpoint();
            long wall = Duration.between(clock.instant(), deadline).toMillis();
            long elapsed = monotonic.getAsLong() - startedNanos;
            long remaining = Math.min(wall, java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(budgetNanos - elapsed));
            if (remaining <= 0) throw new ContractException("DEADLINE_EXCEEDED", "Original inspection deadline elapsed");
            return remaining;
        }
        /** 원래 future의 소유자만 종료 동작을 한 번 등록한다. future 자체는 노출하지 않는다. */
        public void whenStopped(Runnable ownerStop) {
            Objects.requireNonNull(ownerStop);
            if (!stopHookRegistered.compareAndSet(false, true)) throw new IllegalStateException("Inspection owner stop hook already registered");
            stopHook.set(ownerStop);
            // 등록 직전/도중 종료된 요청도 같은 동작을 정확히 한 번 실행한다.
            if (stopped.get()) runStopHook();
        }
        void stop() { stopped.set(true); runStopHook(); }
        private void runStopHook() {
            Runnable ownerStop = stopHook.getAndSet(null);
            if (ownerStop != null) ownerStop.run();
        }
    }
    private final ContractJson contracts;
    private final HostRuntime runtime;
    private final Inspection inspection;
    private final Clock clock;
    private final Set<HostSession> negotiated = ConcurrentHashMap.newKeySet();
    public HostDispatcher(ContractJson contracts, HostRuntime runtime, Inspection inspection, Clock clock) {
        this.contracts = contracts; this.runtime = runtime; this.inspection = inspection; this.clock = clock;
    }
    public CompletionStage<ObjectNode> handle(HostSession session, JsonNode value) {
        contracts.validate("HostRequest", value);
        session.checkOpen();
        ObjectNode request = ContractJson.object(value);
        String method = request.path("method").asText();
        String id = request.path("requestId").asText();
        Instant deadline = Instant.parse(request.path("deadlineAt").asText());
        Instant now = clock.instant();
        long admittedNanos = System.nanoTime();
        if (!now.isBefore(deadline) || deadline.isAfter(now.plusSeconds(120))) {
            throw new ContractException("DEADLINE_EXCEEDED", "Host request deadline is expired or exceeds 120 seconds");
        }
        if (!"hello".equals(method) && !negotiated.contains(session)) {
            throw new ContractException("HANDSHAKE_REQUIRED", "Exact host protocol handshake is required");
        }
        ObjectNode payload = ContractJson.object(request.get("payload"));
        InspectionControl control = "inspect".equals(method)
                ? new InspectionControl(clock, deadline, now, admittedNanos, System::nanoTime) : null;
        CompletionStage<? extends JsonNode> result;
        switch (method) {
            case "hello" -> {
                exactFields(payload, Set.of());
                ObjectNode hello = runtime.hello();
                contracts.validate("HostHello", hello);
                if (!ContractJson.VERSION.equals(hello.path("hostProtocolVersion").asText())) {
                    throw new ContractException("HOST_PROTOCOL_MISMATCH", "The installed host does not expose the exact protocol");
                }
                negotiated.add(session);
                result = CompletableFuture.completedFuture(hello);
            }
            case "inventory" -> { exactFields(payload, Set.of()); result = CompletableFuture.completedFuture(runtime.inventory()); }
            case "describe" -> {
                exactFields(payload, Set.of("bindingId", "actionId"));
                result = CompletableFuture.completedFuture(runtime.describe(string(payload, "bindingId"), string(payload, "actionId")));
            }
            case "dispatch", "prepare" -> {
                Invocation invocation = new Invocation(contracts, payload);
                if (!invocation.contextId().equals(request.path("contextId").asText()) || invocation.deadlineAt().isAfter(deadline)) {
                    throw new ContractException("INVOCATION_PIN_MISMATCH", "Invocation context or deadline differs from its host envelope");
                }
                result = "dispatch".equals(method) ? runtime.dispatch(session, invocation).thenApply(report -> report.wire())
                        : runtime.prepare(session, invocation);
            }
            case "operation.get", "operation.cancel" -> {
                exactFields(payload, Set.of("invocationId"));
                result = "operation.get".equals(method) ? runtime.poll(session, string(payload, "invocationId"))
                        : runtime.cancel(session, string(payload, "invocationId"));
            }
            case "events.since" -> {
                exactFields(payload, Set.of("sequence"));
                String sequence = string(payload, "sequence");
                if (!sequence.matches("0|[1-9][0-9]{0,18}")) throw new ContractException("EVENT_CURSOR_INVALID", "Sequence must be a bounded decimal string");
                try { result = CompletableFuture.completedFuture(runtime.eventsSince(Long.parseLong(sequence))); }
                catch (NumberFormatException exception) { throw new ContractException("EVENT_CURSOR_INVALID", "Sequence exceeds the host range"); }
            }
            case "inspect" -> {
                String contextId = request.path("contextId").asText();
                if (contextId.isBlank()) throw new ContractException("CONTEXT_UNKNOWN", "Inspection needs an installed context");
                control.checkpoint();
                result = inspection.inspect(session, session.context(contextId), payload.deepCopy(), control);
            }
            default -> throw new ContractException("HOST_METHOD_UNSUPPORTED", "Host method is not registered");
        }
        CompletableFuture<ObjectNode> reply = result.handle((data, failure) -> {
            Throwable terminalFailure = failure;
            if (control != null && terminalFailure == null) {
                try { control.checkpoint(); }
                catch (RuntimeException stopped) { terminalFailure = stopped; }
            }
            ObjectNode response = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION)
                    .put("requestId", id).put("eventSequence", Long.toString(runtime.sequence()));
            if (terminalFailure == null && data != null) response.put("status", "ok").set("payload", data.deepCopy());
            else {
                response.put("status", "error");
                Throwable cause = terminalFailure;
                for (int depth = 0; depth < 8 && (cause instanceof java.util.concurrent.CompletionException || cause instanceof java.util.concurrent.ExecutionException) && cause.getCause() != null; depth++) cause = cause.getCause();
                String code = cause instanceof ContractException exception ? exception.code() : "HOST_EXECUTION_FAILED";
                response.set("error", error(code, "dispatch".equals(method) ? "unknown" : "none_confirmed"));
            }
            contracts.validate("HostResponse", response);
            return response;
        }).toCompletableFuture();
        if (control != null) {
            reply.whenComplete((ignored, failure) -> {
                control.stop();
            });
        }
        return reply;
    }
    public static ObjectNode error(String code, String effects) {
        ObjectNode result = ContractJson.newObject().put("code", code).put("message", "The host request did not complete")
                .putNull("subjectId").put("retry", "unknown".equals(effects) ? "reconcile" : "never").put("effects", effects);
        result.putArray("evidenceRefs");
        return result;
    }
    public static String string(ObjectNode object, String name) {
        if (!object.has(name) || !object.get(name).isTextual() || object.get(name).asText().isBlank()) {
            throw new ContractException("CONTRACT_INVALID", "Required text field is unavailable");
        }
        return object.get(name).asText();
    }
    public static void exactFields(ObjectNode object, Set<String> fields) {
        if (object.size() != fields.size() || !fields.stream().allMatch(object::has)) {
            throw new ContractException("CONTRACT_INVALID", "The host method payload has unexpected fields");
        }
    }
}
