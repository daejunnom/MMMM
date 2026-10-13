package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;

/** One closed HostRequest dispatch table. Generic JSON payload does not enable arbitrary methods. */
public final class HostDispatcher {
    @FunctionalInterface public interface Inspection {
        CompletionStage<ObjectNode> inspect(HostSession session, ObjectNode context, ObjectNode payload);
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
        if (!now.isBefore(deadline) || deadline.isAfter(now.plusSeconds(120))) {
            throw new ContractException("DEADLINE_EXCEEDED", "Host request deadline is expired or exceeds 120 seconds");
        }
        if (!"hello".equals(method) && !negotiated.contains(session)) {
            throw new ContractException("HANDSHAKE_REQUIRED", "Exact host protocol handshake is required");
        }
        ObjectNode payload = ContractJson.object(request.get("payload"));
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
                result = inspection.inspect(session, session.context(contextId), payload.deepCopy());
            }
            default -> throw new ContractException("HOST_METHOD_UNSUPPORTED", "Host method is not registered");
        }
        return result.handle((data, failure) -> {
            ObjectNode response = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION)
                    .put("requestId", id).put("eventSequence", Long.toString(runtime.sequence()));
            if (failure == null && data != null) response.put("status", "ok").set("payload", data.deepCopy());
            else {
                response.put("status", "error");
                Throwable cause = failure;
                for (int depth = 0; depth < 8 && (cause instanceof java.util.concurrent.CompletionException || cause instanceof java.util.concurrent.ExecutionException) && cause.getCause() != null; depth++) cause = cause.getCause();
                String code = cause instanceof ContractException exception ? exception.code() : "HOST_EXECUTION_FAILED";
                response.set("error", error(code, "dispatch".equals(method) ? "unknown" : "none_confirmed"));
            }
            contracts.validate("HostResponse", response);
            return response;
        });
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
