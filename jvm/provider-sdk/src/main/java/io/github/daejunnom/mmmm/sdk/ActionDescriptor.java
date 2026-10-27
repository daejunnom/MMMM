package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BigIntegerNode;
import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.DecimalNode;
import com.fasterxml.jackson.databind.node.DoubleNode;
import com.fasterxml.jackson.databind.node.FloatNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ShortNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * A snapshot of the original ActionDescriptor wire contract. Standard Jackson
 * JSON nodes are copied without exposing mutable internal trees.
 * Schema validation does not issue a host binding or approve action execution.
 * Callers must not mutate an input JSON tree concurrently while it is being
 * copied: construction and builder setters do not provide an atomic snapshot
 * of concurrent mutations.
 * Identity checks do not prove independent backing state for custom node
 * subclasses or preempt arbitrary code in their copy/iterator implementations.
 */
public final class ActionDescriptor {
    public enum Side {
        SERVER("server"), CLIENT("client"), EXTERNAL("external");
        private final String wire;
        Side(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum RequiredContext {
        WORLD("world"), DIMENSION("dimension"), EXECUTOR("executor"), ORIGIN("origin"),
        ROTATION("rotation"), ANCHOR("anchor"), SELECTION("selection"), PROJECT("project");
        private final String wire;
        RequiredContext(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum Effect {
        READ("read"), WRITE("write"), UNKNOWN("unknown");
        private final String wire;
        Effect(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum Planning {
        PURE("pure"), UNSUPPORTED("unsupported");
        private final String wire;
        Planning(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum Completion {
        SYNCHRONOUS("synchronous"), JOB("job"), UNOBSERVABLE("unobservable");
        private final String wire;
        Completion(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum Cancellation {
        NONE("none"), QUEUED_ONLY("queued_only"), COOPERATIVE("cooperative");
        private final String wire;
        Cancellation(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum Recovery {
        NONE("none"), PROVIDER_UNDO("provider_undo"), FILE_SNAPSHOT("file_snapshot"),
        EXPLICIT_PATCH("explicit_patch");
        private final String wire;
        Recovery(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum Idempotency {
        READ("read"), PROVIDER_KEYED("provider_keyed"), COORDINATOR_ONLY("coordinator_only"), NONE("none");
        private final String wire;
        Idempotency(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum VerificationRequirement {
        SCHEMA_ONLY("schema_only"), PROVIDER_COMPLETION("provider_completion"),
        INDEPENDENT_READBACK("independent_readback");
        private final String wire;
        VerificationRequirement(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    public enum VersionEvidence {
        DECLARED("declared"), INTERFACE_CHECKED("interface_checked"),
        FIXTURE_VERIFIED("fixture_verified"), RUNTIME_VERIFIED("runtime_verified");
        private final String wire;
        VersionEvidence(String wire) { this.wire = wire; }
        public String wireValue() { return wire; }
    }

    private final ObjectNode value;

    public ActionDescriptor(ContractJson contracts, JsonNode input) {
        required(contracts, "Contract validator");
        ObjectNode source = ContractJson.object(input);
        // Validate before copying to bound the source tree and reject cycles.
        contracts.validate("ActionDescriptor", source);
        ObjectNode snapshot = detachedCopy(source);
        // Only the validated snapshot is retained, even if the input changed
        // between its initial validation and copying.
        contracts.validate("ActionDescriptor", snapshot);
        value = snapshot;
    }

    /** Parse using the SDK's strict UTF-8, duplicate-key and JSON limits. */
    public static ActionDescriptor fromBytes(ContractJson contracts, byte[] bytes) {
        required(bytes, "Descriptor bytes");
        return new ActionDescriptor(contracts, ContractJson.parse(bytes));
    }

    public static Builder builder() { return new Builder(); }

    public ObjectNode wire() { return detachedCopy(value); }
    public String actionId() { return value.get("actionId").textValue(); }
    public String contractVersion() { return value.get("contractVersion").textValue(); }
    public String title() { return value.get("title").textValue(); }
    public String summary() { return value.get("summary").textValue(); }
    public String semanticKind() { return value.get("semanticKind").textValue(); }
    public ObjectNode inputSchema() { return detachedCopy(ContractJson.object(value.get("inputSchema"))); }
    public ObjectNode outputSchema() { return detachedCopy(ContractJson.object(value.get("outputSchema"))); }
    public Side side() { return readEnum(value.get("side").textValue(), Side.values(), Side::wireValue); }

    public List<RequiredContext> requiredContext() {
        List<RequiredContext> contexts = new ArrayList<>();
        for (JsonNode context : value.get("requiredContext")) {
            contexts.add(readEnum(context.textValue(), RequiredContext.values(), RequiredContext::wireValue));
        }
        return List.copyOf(contexts);
    }

    public Effect effect() { return readEnum(value.get("effect").textValue(), Effect.values(), Effect::wireValue); }
    public Planning planning() { return readEnum(value.get("planning").textValue(), Planning.values(), Planning::wireValue); }
    public Completion completion() { return readEnum(value.get("completion").textValue(), Completion.values(), Completion::wireValue); }
    public Cancellation cancellation() { return readEnum(value.get("cancellation").textValue(), Cancellation.values(), Cancellation::wireValue); }
    public Recovery recovery() { return readEnum(value.get("recovery").textValue(), Recovery.values(), Recovery::wireValue); }
    public Idempotency idempotency() { return readEnum(value.get("idempotency").textValue(), Idempotency.values(), Idempotency::wireValue); }
    public List<String> guarantees() { return strings(value.get("guarantees")); }
    public List<String> limitations() { return strings(value.get("limitations")); }
    public List<String> requiredPermissions() { return strings(value.get("requiredPermissions")); }
    public VerificationRequirement verificationRequirement() {
        return readEnum(value.get("verificationRequirement").textValue(), VerificationRequirement.values(), VerificationRequirement::wireValue);
    }
    public String implementationDigest() { return value.get("implementationDigest").textValue(); }
    public VersionEvidence versionEvidence() {
        return readEnum(value.get("versionEvidence").textValue(), VersionEvidence.values(), VersionEvidence::wireValue);
    }

    private static List<String> strings(JsonNode array) {
        List<String> result = new ArrayList<>();
        for (JsonNode item : array) result.add(item.textValue());
        return List.copyOf(result);
    }

    private static <E> E readEnum(String text, E[] values, Function<E, String> wire) {
        for (E candidate : values) if (wire.apply(candidate).equals(text)) return candidate;
        throw new ContractException("CONTRACT_INVALID", "Descriptor enum is outside the original contract");
    }

    private static <T> T required(T value, String name) {
        if (value == null) throw new ContractException("CONTRACT_INVALID", name + " is required");
        return value;
    }

    private record Visit(JsonNode node, int depth) { }

    private static ObjectNode detachedCopy(ObjectNode source) {
        // Reuse the validator's tree and estimated-byte policy before copying
        // and on the returned tree; no encoded-byte check is introduced here.
        ContractJson.checkSnapshotTree(source);
        ObjectNode copy = required(source.deepCopy(), "Copied JSON object");
        IdentityHashMap<JsonNode, Boolean> mutable = new IdentityHashMap<>();
        visit(source, node -> {
            if (!standardImmutable(node)) mutable.put(node, Boolean.TRUE);
        });
        visit(copy, node -> {
            if (mutable.containsKey(node)) {
                throw new ContractException("CONTRACT_INVALID", "JSON copy shares a mutable input node");
            }
        });
        ContractJson.checkSnapshotTree(copy);
        return copy;
    }

    private static void visit(JsonNode root, Consumer<JsonNode> visitor) {
        ArrayDeque<Visit> pending = new ArrayDeque<>();
        pending.add(new Visit(required(root, "JSON node"), 0));
        int scheduled = 1;
        while (!pending.isEmpty()) {
            Visit current = pending.removeLast();
            JsonNode node = current.node();
            visitor.accept(node);
            if (node.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> fields = required(node.fields(), "JSON iterator");
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> field = required(fields.next(), "JSON field");
                    scheduled = schedule(pending, current, field.getValue(), scheduled);
                }
            } else if (node.isArray()) {
                Iterator<JsonNode> children = required(node.iterator(), "JSON iterator");
                while (children.hasNext()) {
                    scheduled = schedule(pending, current, children.next(), scheduled);
                }
            }
        }
    }

    private static int schedule(ArrayDeque<Visit> pending, Visit parent, JsonNode value, int scheduled) {
        JsonNode child = required(value, "JSON child");
        int next = scheduled + 1;
        if (next > 100_000 || parent.depth() >= 96) {
            throw new ContractException("CONTRACT_INVALID", "JSON exceeds the structural limit");
        }
        pending.add(new Visit(child, parent.depth() + 1));
        return next;
    }

    private static boolean standardImmutable(JsonNode node) {
        Class<?> type = node.getClass();
        return type == TextNode.class || type == BooleanNode.class || type == NullNode.class
                || type == IntNode.class || type == LongNode.class || type == ShortNode.class
                || type == BigIntegerNode.class || type == DecimalNode.class
                || type == FloatNode.class || type == DoubleNode.class;
    }

    /** Builds the same original wire contract; no fields are implicitly supplied. */
    public static final class Builder {
        private final ObjectNode draft = ContractJson.newObject();
        private Builder() { }

        public Builder actionId(String value) { return text("actionId", value); }
        public Builder contractVersion(String value) { return text("contractVersion", value); }
        public Builder title(String value) { return text("title", value); }
        public Builder summary(String value) { return text("summary", value); }
        public Builder semanticKind(String value) { return text("semanticKind", value); }
        public Builder inputSchema(ObjectNode value) { return object("inputSchema", value); }
        public Builder outputSchema(ObjectNode value) { return object("outputSchema", value); }
        public Builder side(Side value) { return text("side", required(value, "side").wireValue()); }

        public Builder requiredContext(List<RequiredContext> values) {
            required(values, "requiredContext");
            ArrayNode array = JsonNodeFactory.instance.arrayNode();
            for (RequiredContext value : values) {
                requireArrayRoom(array);
                array.add(required(value, "requiredContext item").wireValue());
            }
            draft.set("requiredContext", array);
            return this;
        }

        public Builder effect(Effect value) { return text("effect", required(value, "effect").wireValue()); }
        public Builder planning(Planning value) { return text("planning", required(value, "planning").wireValue()); }
        public Builder completion(Completion value) { return text("completion", required(value, "completion").wireValue()); }
        public Builder cancellation(Cancellation value) { return text("cancellation", required(value, "cancellation").wireValue()); }
        public Builder recovery(Recovery value) { return text("recovery", required(value, "recovery").wireValue()); }
        public Builder idempotency(Idempotency value) { return text("idempotency", required(value, "idempotency").wireValue()); }
        public Builder guarantees(List<String> values) { return strings("guarantees", values); }
        public Builder limitations(List<String> values) { return strings("limitations", values); }
        public Builder requiredPermissions(List<String> values) { return strings("requiredPermissions", values); }
        public Builder verificationRequirement(VerificationRequirement value) {
            return text("verificationRequirement", required(value, "verificationRequirement").wireValue());
        }
        public Builder implementationDigest(String value) { return text("implementationDigest", value); }
        public Builder versionEvidence(VersionEvidence value) { return text("versionEvidence", required(value, "versionEvidence").wireValue()); }

        public ActionDescriptor build(ContractJson contracts) { return new ActionDescriptor(contracts, draft); }

        private Builder text(String field, String value) {
            draft.put(field, required(value, field));
            return this;
        }

        private Builder object(String field, ObjectNode value) {
            required(value, field);
            // Check the existing bounded JSON rules before a potentially deep
            // copy. Do not serialize and parse the copy, which could change
            // numeric precision inside the caller's open schema object.
            draft.set(field, detachedCopy(value));
            return this;
        }

        private Builder strings(String field, List<String> values) {
            required(values, field);
            ArrayNode array = JsonNodeFactory.instance.arrayNode();
            for (String value : values) {
                requireArrayRoom(array);
                array.add(required(value, field + " item"));
            }
            draft.set(field, array);
            return this;
        }

        private static void requireArrayRoom(ArrayNode array) {
            // ContractJson's complete tree already rejects more than 100,000
            // nodes. Bound the items accumulated from the supplied List.
            if (array.size() >= 100_000) {
                throw new ContractException("CONTRACT_INVALID", "JSON exceeds the structural limit");
            }
        }
    }
}
