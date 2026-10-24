package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;

/** An immutable wire snapshot; it contains no Entity, Level, Java receiver or credential. */
public final class Invocation {
    private final ObjectNode value;
    public Invocation(ContractJson contracts, JsonNode value) {
        contracts.validate("Invocation", value);
        this.value = ContractJson.object(value).deepCopy();
        if (!argumentsDigest().equals(ContractJson.digest(this.value.get("arguments")))
                || !contextDigest().equals(ContractJson.contextDigest(this.value.get("context")))
                || !contextDigest().equals(this.value.path("context").path("contextDigest").asText())) {
            throw new ContractException("INVOCATION_DIGEST_MISMATCH", "Invocation input or context digest changed");
        }
    }
    public ObjectNode wire() { return value.deepCopy(); }
    public ObjectNode arguments() { return ContractJson.object(value.get("arguments")).deepCopy(); }
    public ObjectNode context() { return ContractJson.object(value.get("context")).deepCopy(); }
    public String invocationId() { return value.get("invocationId").asText(); }
    public String operationId() { return value.get("operationId").asText(); }
    public String stepId() { return value.get("stepId").asText(); }
    public String bindingId() { return value.get("bindingId").asText(); }
    public String actionId() { return value.get("actionId").asText(); }
    public String actionContractVersion() { return value.get("actionContractVersion").asText(); }
    public String actionDigest() { return value.get("actionDigest").asText(); }
    public String implementationDigest() { return value.get("implementationDigest").asText(); }
    public String argumentsDigest() { return value.get("argumentsDigest").asText(); }
    public String contextDigest() { return value.get("contextDigest").asText(); }
    public String contextId() { return value.path("context").path("contextId").asText(); }
    public Instant deadlineAt() { return Instant.parse(value.get("deadlineAt").asText()); }
    public String idempotencyKey() { return value.get("idempotencyKey").asText(); }
}
