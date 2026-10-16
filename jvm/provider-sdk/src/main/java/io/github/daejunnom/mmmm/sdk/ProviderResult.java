package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Provider reporting is separate from the Coordinator's independently verified completion. */
public final class ProviderResult {
    private final ObjectNode value;
    public ProviderResult(ContractJson contracts, JsonNode value) {
        contracts.validate("ProviderResult", value);
        this.value = ContractJson.object(value).deepCopy();
    }
    public ObjectNode wire() { return value.deepCopy(); }
    public ObjectNode data() { return ContractJson.object(value.get("data")).deepCopy(); }
    public String status() { return value.get("status").asText(); }
    public String effects() { return value.get("effects").asText(); }
    public String jobHandle() { return value.path("jobHandle").asText(null); }
    public static ProviderResult complete(ContractJson contracts, ObjectNode data, String effects) {
        ObjectNode result = envelope("complete", data, effects);
        return new ProviderResult(contracts, result);
    }
    public static ProviderResult failed(ContractJson contracts, String code, String effects) {
        ObjectNode result = envelope("failed", ContractJson.newObject(), effects);
        ObjectNode diagnostic = ContractJson.newObject().put("code", code).put("severity", "error")
                .put("message", "Provider execution did not complete");
        result.withArray("diagnostics").add(diagnostic);
        return new ProviderResult(contracts, result);
    }
    private static ObjectNode envelope(String status, ObjectNode data, String effects) {
        ObjectNode result = ContractJson.newObject().put("contractVersion", ContractJson.VERSION)
                .put("status", status).put("effects", effects);
        result.set("data", data.deepCopy());
        result.putArray("diagnostics");
        result.putArray("artifacts");
        return result;
    }
}
