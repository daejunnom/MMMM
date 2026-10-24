package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class ImmutableWireSnapshotsTest {
    private final ContractJson contracts = new ContractJson();

    @Test
    void invocationCopiesOriginalInputAndEveryReturnedNestedTree() throws IOException {
        ObjectNode source = OriginalFixtures.example("invocation.json");
        ObjectNode expected = source.deepCopy();
        Invocation invocation = new Invocation(contracts, source);

        source.put("invocationId", "changed-after-construction");
        ContractJson.object(source.get("arguments")).put("text", "changed-input");
        ContractJson.object(source.get("context").get("environment")).put("worldId", "changed-world");
        assertEquals(expected, invocation.wire());

        ObjectNode returnedWire = invocation.wire();
        ContractJson.object(returnedWire.get("context").get("environment")).put("sessionEpoch", "changed-copy");
        invocation.arguments().put("text", "changed-getter");
        ObjectNode returnedContext = invocation.context();
        ((ArrayNode) returnedContext.get("origin")).set(0, IntNode.valueOf(123));
        assertEquals(expected, invocation.wire());
        assertEquals(expected.get("arguments"), invocation.arguments());
        assertEquals(expected.get("context"), invocation.context());
        assertEquals(expected.path("context").path("contextId").asText(), invocation.contextId());
    }

    @ParameterizedTest
    @ValueSource(strings = {"arguments", "context-origin", "argumentsDigest", "contextDigest", "embedded-contextDigest"})
    void staleOrConflictingInvocationDigestsAreRejected(String mutation) throws IOException {
        ObjectNode source = OriginalFixtures.example("invocation.json");
        switch (mutation) {
            case "arguments" -> ContractJson.object(source.get("arguments")).put("text", "changed-without-rehash");
            case "context-origin" -> ((ArrayNode) source.get("context").get("origin")).set(0, IntNode.valueOf(1));
            case "argumentsDigest", "contextDigest" -> source.put(mutation, "0".repeat(64));
            case "embedded-contextDigest" -> ContractJson.object(source.get("context")).put("contextDigest", "0".repeat(64));
            default -> throw new IllegalArgumentException("Unknown regression mutation");
        }
        ContractException failure = assertThrows(ContractException.class, () -> new Invocation(contracts, source));
        assertEquals("INVOCATION_DIGEST_MISMATCH", failure.code());
    }

    @Test
    void providerResultCopiesOriginalInputAndReturnedData() throws IOException {
        ObjectNode source = OriginalFixtures.example("provider-result.json");
        ObjectNode expected = source.deepCopy();
        ProviderResult result = new ProviderResult(contracts, source);
        ContractJson.object(source.get("data")).put("text", "changed-input");
        result.data().put("text", "changed-getter");
        ObjectNode returnedWire = result.wire();
        ContractJson.object(returnedWire.get("data")).put("text", "changed-wire-copy");
        ((ArrayNode) returnedWire.get("diagnostics")).addObject().put("code", "added-to-copy");
        assertEquals(expected, result.wire());
        assertEquals(expected.get("data"), result.data());
    }
}
