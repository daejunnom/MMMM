package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    private static ObjectNode actionExample() throws IOException {
        return ContractJson.object(OriginalFixtures.example("provider-supported.json").path("actions").get(0)).deepCopy();
    }

    @Test
    void actionDescriptorTypedFieldsBuilderAndSharedCanonicalGolden() throws IOException {
        ObjectNode source = actionExample();
        ObjectNode expected = source.deepCopy();
        ActionDescriptor descriptor = new ActionDescriptor(contracts, source);

        assertEquals("fixture:echo_text", descriptor.actionId());
        assertEquals("0.2.0", descriptor.contractVersion());
        assertEquals("Echo text (fixture only)", descriptor.title());
        assertEquals("Returns a string in a structured object. No game or filesystem changes.", descriptor.summary());
        assertEquals("mmmm:diagnostic.echo", descriptor.semanticKind());
        assertEquals("f61ff8630fd33ce19fecd868f9af125c66edf0564fa64e96e0875accf26c24cb", descriptor.implementationDigest());
        assertEquals(ActionDescriptor.Side.SERVER, descriptor.side());
        assertEquals(ActionDescriptor.Effect.READ, descriptor.effect());
        assertEquals(ActionDescriptor.Planning.PURE, descriptor.planning());
        assertEquals(ActionDescriptor.Completion.SYNCHRONOUS, descriptor.completion());
        assertEquals(ActionDescriptor.Cancellation.NONE, descriptor.cancellation());
        assertEquals(ActionDescriptor.Recovery.NONE, descriptor.recovery());
        assertEquals(ActionDescriptor.Idempotency.READ, descriptor.idempotency());
        assertEquals(ActionDescriptor.VerificationRequirement.SCHEMA_ONLY, descriptor.verificationRequirement());
        assertEquals(ActionDescriptor.VersionEvidence.DECLARED, descriptor.versionEvidence());
        assertEquals(List.of(ActionDescriptor.RequiredContext.EXECUTOR), descriptor.requiredContext());
        assertEquals(List.of("returns_input_text"), descriptor.guarantees());
        assertEquals(List.of(), descriptor.limitations());
        assertEquals(List.of("diagnostic.read"), descriptor.requiredPermissions());
        assertEquals(expected.get("inputSchema"), descriptor.inputSchema());
        assertEquals(expected.get("outputSchema"), descriptor.outputSchema());

        ObjectNode input = descriptor.inputSchema();
        ObjectNode output = descriptor.outputSchema();
        var contexts = new ArrayList<>(descriptor.requiredContext());
        var guarantees = new ArrayList<>(descriptor.guarantees());
        var limits = new ArrayList<>(descriptor.limitations());
        var permissions = new ArrayList<>(descriptor.requiredPermissions());
        var builder = ActionDescriptor.builder()
                .actionId(descriptor.actionId()).contractVersion(descriptor.contractVersion())
                .title(descriptor.title()).summary(descriptor.summary()).semanticKind(descriptor.semanticKind())
                .inputSchema(input).outputSchema(output).side(descriptor.side()).requiredContext(contexts)
                .effect(descriptor.effect()).planning(descriptor.planning()).completion(descriptor.completion())
                .cancellation(descriptor.cancellation()).recovery(descriptor.recovery()).idempotency(descriptor.idempotency())
                .guarantees(guarantees).limitations(limits).requiredPermissions(permissions)
                .verificationRequirement(descriptor.verificationRequirement())
                .implementationDigest(descriptor.implementationDigest()).versionEvidence(descriptor.versionEvidence());

        // The builder owns each setter value even before build; returned DTOs also
        // remain stable if the builder itself is later reused.
        input.put("callerChanged", true); output.put("callerChanged", true);
        contexts.add(ActionDescriptor.RequiredContext.WORLD); guarantees.add("caller_changed");
        limits.add("caller_changed"); permissions.add("caller.changed");
        ActionDescriptor rebuilt = builder.build(contracts);
        builder.title("builder changed later");
        assertEquals(expected, rebuilt.wire());

        try (var goldenStream = ImmutableWireSnapshotsTest.class.getResourceAsStream("/action-descriptor-canonical.json")) {
            assertNotNull(goldenStream);
            byte[] golden = goldenStream.readNBytes(2049);
            assertTrue(golden.length <= 2048, "Canonical test vector has a finite size");
            assertEquals(-1, goldenStream.read());
            assertArrayEquals(golden, ContractJson.canonical(expected));
            assertArrayEquals(golden, ContractJson.canonical(descriptor.wire()));
            assertArrayEquals(golden, ContractJson.canonical(rebuilt.wire()));
            assertEquals(expected, ActionDescriptor.fromBytes(contracts, golden).wire());
        }

        String digest = ContractJson.digest(expected);
        source.put("title", "source changed");
        ContractJson.object(source.get("inputSchema")).put("sourceChanged", true);
        descriptor.inputSchema().put("getterChanged", true);
        descriptor.outputSchema().put("getterChanged", true);
        descriptor.wire().put("title", "wire changed");
        assertThrows(UnsupportedOperationException.class, () -> descriptor.requiredContext().clear());
        assertThrows(UnsupportedOperationException.class, () -> descriptor.guarantees().clear());
        assertThrows(UnsupportedOperationException.class, () -> descriptor.limitations().add("changed"));
        assertThrows(UnsupportedOperationException.class, () -> descriptor.requiredPermissions().clear());
        assertEquals(expected, descriptor.wire());
        assertEquals(digest, ContractJson.digest(descriptor.wire()));
        assertEquals(expected, rebuilt.wire());
    }

    @Test
    void actionDescriptorRejectsMissingNullUnknownAndInvalidEnums() throws IOException {
        ObjectNode example = actionExample();
        assertThrows(ContractException.class, () -> ActionDescriptor.builder().build(contracts));
        String[] required = {"actionId", "contractVersion", "title", "summary", "semanticKind",
                "inputSchema", "outputSchema", "side", "requiredContext", "effect", "planning",
                "completion", "cancellation", "recovery", "idempotency", "guarantees", "limitations",
                "requiredPermissions", "verificationRequirement", "implementationDigest", "versionEvidence"};
        for (String field : required) {
            ObjectNode missing = example.deepCopy(); missing.remove(field);
            assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, missing), "missing " + field);
            ObjectNode explicitNull = example.deepCopy(); explicitNull.putNull(field);
            assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, explicitNull), "null " + field);
        }
        ObjectNode unknown = example.deepCopy(); unknown.put("unknownField", true);
        assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, unknown));
        for (String field : List.of("side", "effect", "planning", "completion", "cancellation", "recovery",
                "idempotency", "verificationRequirement", "versionEvidence")) {
            ObjectNode invalid = example.deepCopy(); invalid.put(field, "invalid_enum");
            assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, invalid), field);
        }
        ObjectNode badContext = example.deepCopy(); ((ArrayNode) badContext.get("requiredContext")).add("invalid_context");
        assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, badContext));
        for (String field : List.of("requiredContext", "guarantees", "requiredPermissions")) {
            ObjectNode duplicate = example.deepCopy(); ArrayNode items = (ArrayNode) duplicate.get(field);
            items.add(items.get(0).asText());
            assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, duplicate), "duplicate " + field);
        }
    }

    @Test
    void actionDescriptorPreservesOpenSchemasListOrderAndAllowedDuplicates() throws IOException {
        ObjectNode example = actionExample();
        example.put("contractVersion", "9.8.7");
        ((ArrayNode) example.get("requiredContext")).add("world");
        ((ArrayNode) example.get("guarantees")).add("another_guarantee");
        ((ArrayNode) example.get("limitations")).add("same").add("same");
        ((ArrayNode) example.get("requiredPermissions")).add("diagnostic.extra");
        BigDecimal precise = new BigDecimal("0.123456789012345678901");
        ContractJson.object(example.get("inputSchema")).put("x-precise", precise);
        ContractJson.object(example.get("inputSchema")).put("x-negative-zero", -0.0d);
        ContractJson.object(example.get("outputSchema")).put("x-open", "preserved");
        ActionDescriptor descriptor = new ActionDescriptor(contracts, example);
        assertEquals("9.8.7", descriptor.contractVersion());
        assertEquals(List.of(ActionDescriptor.RequiredContext.EXECUTOR, ActionDescriptor.RequiredContext.WORLD), descriptor.requiredContext());
        assertEquals(List.of("returns_input_text", "another_guarantee"), descriptor.guarantees());
        assertEquals(List.of("same", "same"), descriptor.limitations());
        assertEquals(List.of("diagnostic.read", "diagnostic.extra"), descriptor.requiredPermissions());
        assertEquals(precise, descriptor.inputSchema().get("x-precise").decimalValue());
        long negativeZero = Double.doubleToRawLongBits(-0.0d);
        assertEquals(negativeZero, Double.doubleToRawLongBits(descriptor.inputSchema().get("x-negative-zero").doubleValue()));
        ActionDescriptor rebuilt = ActionDescriptor.builder()
                .actionId(descriptor.actionId()).contractVersion(descriptor.contractVersion())
                .title(descriptor.title()).summary(descriptor.summary()).semanticKind(descriptor.semanticKind())
                .inputSchema(descriptor.inputSchema()).outputSchema(descriptor.outputSchema())
                .side(descriptor.side()).requiredContext(descriptor.requiredContext()).effect(descriptor.effect())
                .planning(descriptor.planning()).completion(descriptor.completion()).cancellation(descriptor.cancellation())
                .recovery(descriptor.recovery()).idempotency(descriptor.idempotency()).guarantees(descriptor.guarantees())
                .limitations(descriptor.limitations()).requiredPermissions(descriptor.requiredPermissions())
                .verificationRequirement(descriptor.verificationRequirement())
                .implementationDigest(descriptor.implementationDigest()).versionEvidence(descriptor.versionEvidence())
                .build(contracts);
        assertEquals(precise, rebuilt.inputSchema().get("x-precise").decimalValue());
        assertEquals(negativeZero, Double.doubleToRawLongBits(rebuilt.inputSchema().get("x-negative-zero").doubleValue()));
        assertEquals("preserved", descriptor.outputSchema().path("x-open").asText());
        assertEquals(example, descriptor.wire());
    }

    @Test
    void actionDescriptorRejectsCyclesAndDuplicateRawKeysBeforeCopy() throws IOException {
        ObjectNode cyclic = actionExample();
        ObjectNode nested = ContractJson.newObject(); nested.set("self", nested);
        cyclic.set("inputSchema", nested);
        assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, cyclic));

        String raw = new String(ContractJson.bytes(actionExample()), StandardCharsets.UTF_8);
        String duplicate = raw.replaceFirst("\"actionId\":", "\"actionId\":\"duplicate:action\",\"actionId\":");
        assertTrue(!raw.equals(duplicate), "Duplicate-key mutation must target the original action field");
        assertThrows(ContractException.class, () -> ActionDescriptor.fromBytes(contracts, duplicate.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void actionDescriptorPreservesValidTreeWhenSerializedBytesExceedWireLimit() throws IOException {
        ObjectNode source = actionExample();
        ObjectNode schema = ContractJson.object(source.get("inputSchema"));
        String text = "a".repeat(8_100_000);
        schema.put("x-long-text", text);
        ArrayNode flags = schema.putArray("x-false-flags");
        for (int i = 0; i < 60_000; i++) flags.add(false);

        // This finite authored tree remains within the existing validator's
        // estimated budget; its actual serialized bytes exceed the wire cap.
        contracts.validate("ActionDescriptor", source);
        assertThrows(ContractException.class, () -> ContractJson.bytes(source));
        ActionDescriptor descriptor = new ActionDescriptor(contracts, source);
        ObjectNode copied = descriptor.inputSchema();
        assertEquals(8_100_000, copied.path("x-long-text").asText().length());
        assertEquals(text, copied.path("x-long-text").asText());
        assertEquals(60_000, copied.path("x-false-flags").size());
        assertEquals(flags, copied.get("x-false-flags"));
    }

    private static final class SelfCopyingObjectNode extends ObjectNode {
        private static final long serialVersionUID = 1L;

        private SelfCopyingObjectNode() { super(com.fasterxml.jackson.databind.node.JsonNodeFactory.instance); }
        @Override public ObjectNode deepCopy() { return this; }
    }

    @Test
    void actionDescriptorRejectsMutableNodeThatReturnsItselfFromDeepCopy() throws IOException {
        ObjectNode source = actionExample();
        SelfCopyingObjectNode aliased = new SelfCopyingObjectNode();
        aliased.put("type", "object");
        source.set("inputSchema", aliased);
        // The original schema accepts this nested object; the private copy must
        // still reject its mutable identity alias before it can escape.
        contracts.validate("ActionDescriptor", source);
        assertThrows(ContractException.class, () -> new ActionDescriptor(contracts, source));
        assertThrows(ContractException.class, () -> ActionDescriptor.builder().inputSchema(aliased));
    }

    @Test
    void actionDescriptorBuilderRejectsOversizedFiniteListBeforeBuild() {
        assertThrows(ContractException.class,
                () -> ActionDescriptor.builder().guarantees(Collections.nCopies(100_001, "x")));
    }
}
