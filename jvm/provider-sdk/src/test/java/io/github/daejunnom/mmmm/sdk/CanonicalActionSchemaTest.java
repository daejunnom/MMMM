package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 원본 예시는 action schema의 정본 URI 연결과 그 연결의 격리 경계를 다루지 않는다. */
final class CanonicalActionSchemaTest {
    private static final String RESOURCE_REF = "urn:mmmm:contracts:0.2.0#/$defs/ResourceRef";
    private final ContractJson contracts = new ContractJson();

    @Test
    void preparedChangeUsesTheUnchangedOriginalResourceContract() throws IOException {
        ObjectNode schema = preparedChangeSchema();
        ObjectNode snapshot = schema.deepCopy();
        var compiled = contracts.compileActionSchema(schema);
        ObjectNode input = preparedChange();

        assertDoesNotThrow(() -> ContractJson.validateSchema(compiled, input));
        assertEquals(snapshot, schema, "Compiling must not rewrite the caller's schema tree");
        assertEquals(RESOURCE_REF, schema.path("properties").path("preparedChange").path("$ref").asText());

        // Mutation after compilation must not change either the original definition or the compiled schema.
        schema.withObject("properties").withObject("preparedChange").remove("$ref");
        ObjectNode invalid = input.deepCopy();
        invalid.withObject("preparedChange").put("sha256", "untrusted-hash");
        assertThrows(ContractException.class, () -> ContractJson.validateSchema(compiled, invalid));
        assertDoesNotThrow(() -> ContractJson.validateSchema(compiled, input));
    }

    @Test
    void canonicalResourceRejectsUnknownFieldsHashChangesAndInvalidSizes() throws IOException {
        var compiled = contracts.compileActionSchema(preparedChangeSchema());
        ObjectNode input = preparedChange();
        ObjectNode wrongHash = input.deepCopy();
        wrongHash.withObject("preparedChange").put("sha256", "F".repeat(64));
        ObjectNode wrongLength = input.deepCopy();
        wrongLength.withObject("preparedChange").put("sha256", "f".repeat(63));
        ObjectNode negativeSize = input.deepCopy();
        negativeSize.withObject("preparedChange").put("sizeBytes", -1);
        ObjectNode fractionalSize = input.deepCopy();
        fractionalSize.withObject("preparedChange").put("sizeBytes", 0.5);
        ObjectNode unknownField = input.deepCopy();
        unknownField.withObject("preparedChange").put("path", "untrusted-path");
        ObjectNode missingHash = input.deepCopy();
        missingHash.withObject("preparedChange").remove("sha256");
        for (ObjectNode invalid : new ObjectNode[] {
                wrongHash, wrongLength, negativeSize, fractionalSize, unknownField, missingHash
        }) {
            assertThrows(ContractException.class, () -> ContractJson.validateSchema(compiled, invalid));
        }
        ObjectNode boundary = input.deepCopy();
        boundary.withObject("preparedChange").put("sizeBytes", 9_007_199_254_740_991L);
        assertDoesNotThrow(() -> ContractJson.validateSchema(compiled, boundary));
        boundary.withObject("preparedChange").put("sizeBytes", 9_007_199_254_740_992L);
        assertThrows(ContractException.class, () -> ContractJson.validateSchema(compiled, boundary));
    }

    @Test
    void preparedChangeEnvelopeStillUsesItsOwnClosedActionSchema() throws IOException {
        var compiled = contracts.compileActionSchema(preparedChangeSchema());
        ObjectNode extraArgument = preparedChange().put("bypass", true);
        assertThrows(ContractException.class, () -> ContractJson.validateSchema(compiled, extraArgument));
        assertThrows(ContractException.class, () -> ContractJson.validateSchema(compiled, ContractJson.newObject()));
    }

    @Test
    void providerLocalDefinitionCannotShadowTheCanonicalResourceContract() throws IOException {
        ObjectNode schema = preparedChangeSchema();
        schema.putObject("$defs").put("ResourceRef", true);
        ObjectNode snapshot = schema.deepCopy();
        var compiled = contracts.compileActionSchema(schema);
        ObjectNode invalid = preparedChange();
        invalid.withObject("preparedChange").put("sha256", "provider-local-schema-would-accept-this");
        assertThrows(ContractException.class, () -> ContractJson.validateSchema(compiled, invalid));
        assertEquals(snapshot, schema);
    }

    @Test
    void providerCannotRebindTheCanonicalUriWithItsOwnSchemaId() {
        ObjectNode schema = preparedChangeSchema().put("$id", "urn:mmmm:contracts:0.2.0");
        ContractException failure = assertThrows(ContractException.class, () -> contracts.compileActionSchema(schema));
        assertEquals("ACTION_SCHEMA_INVALID", failure.code());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "urn:mmmm:contracts:0.1.0#/$defs/ResourceRef",
            "URN:mmmm:contracts:0.2.0#/$defs/ResourceRef",
            "urn:mmmm:contracts:0.2.0",
            "urn:mmmm:contracts:0.2.0#/$defs/NotAContract",
            "urn:mmmm:contracts:0.2.0#/$defs/ResourceRef/properties/NotDefined",
            "urn:mmmm:contracts:0.2.0#/$defs/%52esourceRef",
            "https://example.invalid/mmmm.schema.json#/$defs/ResourceRef",
            "file:///mmmm.schema.json#/$defs/ResourceRef"
    })
    void onlyTheExactApprovedCanonicalUriCanResolve(String reference) {
        ObjectNode schema = preparedChangeSchema();
        schema.withObject("properties").withObject("preparedChange").put("$ref", reference);
        ContractException failure = assertThrows(ContractException.class, () -> contracts.compileActionSchema(schema));
        assertEquals("EXTERNAL_SCHEMA_REF", failure.code());
    }

    @ParameterizedTest
    @ValueSource(strings = {"$dynamicRef", "$recursiveRef"})
    void canonicalAllowanceDoesNotOpenOtherReferenceKeywords(String keyword) {
        ObjectNode schema = ContractJson.newObject().put(keyword, RESOURCE_REF);
        ContractException failure = assertThrows(ContractException.class, () -> contracts.compileActionSchema(schema));
        assertEquals("EXTERNAL_SCHEMA_REF", failure.code());
    }

    private static ObjectNode preparedChangeSchema() {
        ObjectNode schema = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        schema.putObject("properties").putObject("preparedChange").put("$ref", RESOURCE_REF);
        schema.putArray("required").add("preparedChange");
        return schema;
    }

    private static ObjectNode preparedChange() throws IOException {
        ObjectNode value = ContractJson.newObject();
        value.set("preparedChange", OriginalFixtures.example("asset.json").path("resource").deepCopy());
        return value;
    }
}
