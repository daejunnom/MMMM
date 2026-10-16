package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 원본 호출 예시는 호스트 복구 토큰의 비공개 자료·승인 승계·일회성 소비를 다루지 않는다. */
final class ScopedUndoTokensTest {
    private static final UUID PLAYER = UUID.fromString("da0135a6-0b66-4df4-a95a-1838b312e403");
    private static final String UNDO_ACTION = "fixture:undo_echo";
    private final ContractJson contracts = new ContractJson();

    @Test void receiptContainsOnlyFrozenMetadataAndIndependentCanonicalDigests() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession session = installed(source.context(), PLAYER);
        ObjectNode token = token(); ObjectNode originalToken = token.deepCopy();
        ObjectNode receipt = store.capture(session, source, UNDO_ACTION, token);
        assertEquals(Set.of("contractVersion", "tokenRecordId", "tokenRecordDigest", "principalRef",
                "sessionEpoch", "gameInstanceId", "side", "playerId", "bindingId", "sourceActionId",
                "sourceActionDigest", "sourceImplementationDigest", "sourceArgumentsDigest", "sourceContextDigest",
                "sourceOperationId", "sourceStepId", "sourceInvocationId", "undoActionId", "sourceContext",
                "privateTokenSha256"), fieldNames(receipt));
        assertFalse(receipt.toString().contains("opaque-native-original"));
        assertTrue(receipt.path("tokenRecordId").asText().startsWith("undo-"));
        ObjectNode digestProjection = receipt.deepCopy();
        String recordDigest = digestProjection.remove("tokenRecordDigest").asText();
        assertEquals(ContractJson.digest(digestProjection), recordDigest);
        assertEquals(ContractJson.digest(originalToken), receipt.path("privateTokenSha256").asText());
        assertEquals(source.actionId(), receipt.path("sourceActionId").asText());
        assertEquals(source.actionDigest(), receipt.path("sourceActionDigest").asText());
        assertEquals(source.implementationDigest(), receipt.path("sourceImplementationDigest").asText());
        assertEquals(source.argumentsDigest(), receipt.path("sourceArgumentsDigest").asText());
        assertEquals(source.contextDigest(), receipt.path("sourceContextDigest").asText());
        assertEquals(source.context(), receipt.path("sourceContext"));
        ObjectNode frozenReceipt = receipt.deepCopy();
        token.put("nativeState", "changed after capture");
        receipt.put("tokenRecordDigest", "changed after return");
        receipt.withObject("sourceContext").put("principalRef", "changed-after-return");
        assertEquals(frozenReceipt, store.receipt(session, source));
        ObjectNode returned = store.receipt(session, source); returned.remove("sourceContext");
        assertEquals(frozenReceipt, store.receipt(session, source));
        assertEquals(originalToken, store.claim(session, recovery(source, frozenReceipt, "recovery-1")));
    }

    @Test void currentPolicyApprovalCanRecoverAfterSourceSessionClosesButReceiptRemainsOriginal() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession original = installed(source.context(), PLAYER);
        ObjectNode receipt = store.capture(original, source, UNDO_ACTION, token());
        ObjectNode currentContext = source.context().put("policyRevision", "0".repeat(64));
        currentContext.put("contextDigest", ContractJson.contextDigest(currentContext));
        HostSession approved = installed(currentContext, PLAYER);
        assertFalse(source.contextDigest().equals(currentContext.path("contextDigest").asText()));
        assertCode("RECOVERY_SCOPE_MISMATCH", () -> store.receipt(approved, source));
        ObjectNode changedSourceWire = source.wire(); changedSourceWire.set("context", currentContext);
        assertCode("RECOVERY_SCOPE_MISMATCH", () -> store.receipt(approved, invocation(changedSourceWire)));
        assertEquals(receipt, store.receipt(original, source));
        ObjectNode recoveryWire = recovery(source, receipt, "recovery-1").wire(); recoveryWire.set("context", currentContext);
        Invocation recovery = invocation(recoveryWire);
        original.close();
        ObjectNode claimed = store.claim(approved, recovery);
        assertEquals(token(), claimed); claimed.put("nativeState", "mutated callback copy");
        assertCode("RECOVERY_EXPIRED", () -> store.claim(approved, recovery));
        ObjectNode nextRecoveryWire = recovery.wire().put("invocationId", "recovery-2");
        assertCode("RECOVERY_EXPIRED", () -> store.claim(approved, invocation(nextRecoveryWire)));
        HostSession originalContextObserver = installed(source.context(), PLAYER);
        assertEquals(receipt, store.receipt(originalContextObserver, source));
        assertEquals(source.context(), receipt.path("sourceContext"));
        assertEquals(source.contextDigest(), receipt.path("sourceContextDigest").asText());
    }

    @Test void changedReferencesAndArgumentShapeCannotConsumeTheValidToken() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession session = installed(source.context(), PLAYER);
        ObjectNode receipt = store.capture(session, source, UNDO_ACTION, token());
        Invocation valid = recovery(source, receipt, "recovery-1");
        for (String field : List.of("tokenRecordId", "tokenRecordDigest", "sourceOperationId",
                "sourceStepId", "sourceInvocationId")) {
            ObjectNode wire = valid.wire(); wire.withObject("arguments").put(field, "changed-reference");
            assertCode("tokenRecordId".equals(field) ? "RECOVERY_EXPIRED" : "RECOVERY_SCOPE_MISMATCH",
                    () -> store.claim(session, invocation(wire)));
        }
        for (String field : List.of("tokenRecordId", "tokenRecordDigest", "sourceOperationId",
                "sourceStepId", "sourceInvocationId")) {
            ObjectNode missing = valid.wire(); missing.withObject("arguments").remove(field);
            assertCode("RECOVERY_ARGUMENTS_INVALID", () -> store.claim(session, invocation(missing)));
            ObjectNode wrongType = valid.wire(); wrongType.withObject("arguments").put(field, 1);
            assertCode("RECOVERY_ARGUMENTS_INVALID", () -> store.claim(session, invocation(wrongType)));
        }
        ObjectNode extra = valid.wire(); extra.withObject("arguments").put("privateToken", "untrusted");
        assertCode("RECOVERY_ARGUMENTS_INVALID", () -> store.claim(session, invocation(extra)));
        assertEquals(token(), store.claim(session, valid));
    }

    @Test void changedOwnerBindingUndoActionOrTargetContextCannotCrossTheTokenBoundary() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession session = installed(source.context(), PLAYER);
        ObjectNode receipt = store.capture(session, source, UNDO_ACTION, token());
        Invocation valid = recovery(source, receipt, "recovery-1");
        HostSession otherPlayer = installed(source.context(), UUID.fromString("88148c9c-eabd-4fbe-9870-64378924d5fb"));
        assertCode("RECOVERY_SCOPE_MISMATCH", () -> store.claim(otherPlayer, valid));
        for (String field : List.of("bindingId", "actionId")) {
            ObjectNode wire = valid.wire(); wire.put(field, "actionId".equals(field) ? "fixture:other_undo" : "other-binding");
            assertCode("RECOVERY_SCOPE_MISMATCH", () -> store.claim(session, invocation(wire)));
        }
        List<Consumer<ObjectNode>> contextChanges = List.of(
                context -> context.put("principalRef", "other-principal"),
                context -> context.withObject("environment").put("sessionEpoch", "other-epoch"),
                context -> context.withObject("environment").put("gameInstanceId", "other-game"),
                context -> context.withObject("environment").put("side", "client"),
                context -> context.withObject("environment").put("worldId", "other-world"),
                context -> { context.put("projectId", "other-project"); context.withObject("scope").put("projectId", "other-project"); },
                context -> context.put("contextId", "other-context"),
                context -> context.put("dimension", "minecraft:the_nether"),
                context -> context.put("selectionRef", "other-selection"),
                context -> context.put("executorHandle", "other-executor"),
                context -> context.put("anchor", "eyes"),
                context -> context.putArray("origin").add(1).add(64).add(0),
                context -> context.putArray("rotationDegrees").add(1).add(0),
                context -> ((ArrayNode) context.withObject("scope").get("resourceIds")).add("other-resource"));
        for (Consumer<ObjectNode> change : contextChanges) {
            ObjectNode context = source.context(); change.accept(context);
            context.put("contextDigest", ContractJson.contextDigest(context));
            HostSession changedSession = installed(context, PLAYER);
            ObjectNode wire = valid.wire(); wire.set("context", context);
            assertCode("RECOVERY_SCOPE_MISMATCH", () -> store.claim(changedSession, invocation(wire)));
        }
        ObjectNode uninstalledWire = valid.wire();
        ObjectNode uninstalledContext = uninstalledWire.withObject("context");
        uninstalledContext.put("anchor", "eyes");
        uninstalledContext.put("contextDigest", ContractJson.contextDigest(uninstalledContext));
        assertCode("RECOVERY_SCOPE_MISMATCH", () -> store.claim(session, invocation(uninstalledWire)));
        assertEquals(token(), store.claim(session, valid));
    }

    @Test void sourceCannotReplaceFrozenMaterialOrReadItWithChangedPinsAndCloseClearsTheGeneration() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession session = installed(source.context(), PLAYER);
        assertNull(store.receipt(session, source));
        ObjectNode receipt = store.capture(session, source, UNDO_ACTION, token());
        assertCode("UNDO_TOKEN_CONFLICT", () -> store.capture(session, source, UNDO_ACTION, token()));
        ObjectNode changed = source.wire(); changed.withObject("arguments").put("text", "changed");
        Invocation changedSource = invocation(changed);
        assertCode("UNDO_TOKEN_CONFLICT", () -> store.capture(session, changedSource, "fixture:other_undo", token()));
        assertCode("RECOVERY_SCOPE_MISMATCH", () -> store.receipt(session, changedSource));
        ObjectNode other = source.wire().put("invocationId", "other-source");
        assertNull(store.receipt(session, invocation(other)));
        assertEquals(receipt, store.receipt(session, source));
        store.clear();
        assertNull(store.receipt(session, source));
        assertCode("RECOVERY_EXPIRED", () -> store.claim(session, recovery(source, receipt, "recovery-1")));
        session.close();
        assertCode("SESSION_EXPIRED", () -> store.capture(session, source, UNDO_ACTION, token()));
        assertCode("SESSION_EXPIRED", () -> store.claim(session, recovery(source, receipt, "recovery-2")));
    }

    @Test void byteAndRecordLimitsRejectNewMaterialWithoutEvictingExistingReceipts() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession session = installed(source.context(), PLAYER);
        ObjectNode oversized = ContractJson.newObject().put("value", "x".repeat(ScopedUndoTokens.MAX_PRIVATE_TOKEN_BYTES));
        assertCode("UNDO_TOKEN_LIMIT", () -> store.capture(session, source, UNDO_ACTION, oversized));
        ObjectNode boundary = ContractJson.newObject().put("value", "");
        int overhead = ContractJson.bytes(boundary).length;
        boundary.put("value", "x".repeat(ScopedUndoTokens.MAX_PRIVATE_TOKEN_BYTES - overhead));
        assertEquals(ScopedUndoTokens.MAX_PRIVATE_TOKEN_BYTES, ContractJson.bytes(boundary).length);
        ObjectNode first = store.capture(session, source, UNDO_ACTION, boundary);
        ObjectNode wire = source.wire();
        for (int index = 1; index < ScopedUndoTokens.MAX_RECORDS; index++) {
            wire.put("invocationId", "source-" + index);
            assertNotNull(store.capture(session, new Invocation(contracts, wire), UNDO_ACTION, ContractJson.newObject()));
        }
        Invocation overflow = new Invocation(contracts, wire.put("invocationId", "source-overflow"));
        assertCode("UNDO_TOKEN_LIMIT", () -> store.capture(session, overflow, UNDO_ACTION, ContractJson.newObject()));
        assertEquals(first, store.receipt(session, source));
        assertEquals(boundary, store.claim(session, recovery(source, first, "recovery-1")));
    }

    @Test void largeSourceArgumentsAndContextReceiptsArePartOfTheRecordBudget() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession session = installed(source.context(), PLAYER);
        ObjectNode largeWire = source.wire().put("invocationId", "source-large-record");
        largeWire.withObject("arguments").put("payload", "x".repeat(ScopedUndoTokens.MAX_RECORD_BYTES));
        Invocation largeSource = invocation(largeWire);
        assertCode("UNDO_TOKEN_LIMIT", () -> store.capture(session, largeSource, UNDO_ACTION, token()));
        assertNull(store.receipt(session, largeSource));

        ObjectNode largeContext = source.context();
        ArrayNode resources = (ArrayNode) largeContext.withObject("scope").get("resourceIds");
        for (int index = 0; index < 1024; index++) resources.add("resource-" + index + "-" + "x".repeat(64));
        largeContext.put("contextDigest", ContractJson.contextDigest(largeContext));
        assertTrue(ContractJson.bytes(largeContext).length > ScopedUndoTokens.MAX_RECEIPT_BYTES);
        ObjectNode largeReceiptWire = source.wire().put("invocationId", "source-large-receipt");
        largeReceiptWire.set("context", largeContext);
        Invocation largeReceiptSource = invocation(largeReceiptWire);
        HostSession largeContextSession = installed(largeContext, PLAYER);
        assertCode("UNDO_TOKEN_LIMIT", () -> store.capture(largeContextSession, largeReceiptSource, UNDO_ACTION, token()));
        assertNull(store.receipt(largeContextSession, largeReceiptSource));
        ObjectNode receipt = store.capture(session, source, UNDO_ACTION, token());
        assertEquals(token(), store.claim(session, recovery(source, receipt, "recovery-1")));
    }

    @Test void nonJsonProviderMaterialIsRejectedBeforeCopyingOrRegisteringTheSource() throws IOException {
        ScopedUndoTokens store = new ScopedUndoTokens();
        Invocation source = source(); HostSession session = installed(source.context(), PLAYER);
        ObjectNode cyclic = ContractJson.newObject(); cyclic.set("cycle", cyclic);
        assertCode("CONTRACT_INVALID", () -> store.capture(session, source, UNDO_ACTION, cyclic));
        ObjectNode binary = ContractJson.newObject().put("nativeState", new byte[] {1});
        assertCode("CONTRACT_INVALID", () -> store.capture(session, source, UNDO_ACTION, binary));
        assertNull(store.receipt(session, source));
        ObjectNode receipt = store.capture(session, source, UNDO_ACTION, token());
        assertEquals(token(), store.claim(session, recovery(source, receipt, "recovery-1")));
    }

    private Invocation source() throws IOException {
        Path file = Path.of(System.getProperty("mmmm.checkout"), "examples", "invocation.json");
        try (var input = Files.newInputStream(file)) {
            return new Invocation(contracts, ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1)));
        }
    }

    private Invocation recovery(Invocation source, ObjectNode receipt, String id) {
        ObjectNode wire = source.wire();
        wire.put("invocationId", id).put("stepId", "recover-step").put("actionId", UNDO_ACTION);
        ObjectNode references = ContractJson.newObject();
        for (String field : List.of("tokenRecordId", "tokenRecordDigest", "sourceOperationId",
                "sourceStepId", "sourceInvocationId")) references.set(field, receipt.get(field).deepCopy());
        wire.set("arguments", references);
        return invocation(wire);
    }

    private Invocation invocation(ObjectNode wire) {
        wire.put("argumentsDigest", ContractJson.digest(wire.path("arguments")));
        wire.put("contextDigest", ContractJson.contextDigest(wire.path("context")));
        return new Invocation(contracts, wire);
    }

    private HostSession installed(ObjectNode context, UUID player) {
        JsonNode environment = context.path("environment");
        HostSession session = new HostSession(context.path("principalRef").asText(), environment.path("sessionEpoch").asText(),
                environment.path("gameInstanceId").asText(), environment.path("side").asText(), player, Set.of(), true);
        session.installContext(contracts, context);
        return session;
    }

    private static ObjectNode token() {
        return ContractJson.newObject().put("nativeState", "opaque-native-original");
    }

    private static Set<String> fieldNames(ObjectNode value) {
        Set<String> fields = new java.util.HashSet<>(); value.fieldNames().forEachRemaining(fields::add); return fields;
    }

    private static void assertCode(String code, Runnable operation) {
        assertEquals(code, assertThrows(ContractException.class, operation::run).code());
    }
}
