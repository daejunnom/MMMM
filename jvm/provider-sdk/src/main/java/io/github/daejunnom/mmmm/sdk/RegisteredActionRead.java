package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Original immutable read request; reading never allocates an operation or fake Invocation. */
public final class RegisteredActionRead {
    private final ObjectNode value;
    public RegisteredActionRead(ContractJson contracts, JsonNode value) {
        contracts.validate("RegisteredActionRequest", value);
        this.value = ContractJson.object(value).deepCopy();
    }
    public ObjectNode wire() { return value.deepCopy(); }
    public ObjectNode arguments() { return ContractJson.object(value.get("arguments")).deepCopy(); }
    public String contextId() { return value.path("contextId").asText(); }
    public String bindingId() { return value.path("bindingId").asText(); }
    public String actionId() { return value.path("actionId").asText(); }
    public String actionDigest() { return value.path("actionDigest").asText(); }
}
