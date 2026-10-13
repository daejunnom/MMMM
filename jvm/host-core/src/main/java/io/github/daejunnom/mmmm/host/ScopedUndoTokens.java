package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * 한 호스트 generation의 제공자 복구 자료를 보관한다. 공개 영수증과 비공개 제공자
 * 토큰은 별도로 동결하며, 새 승인 세션에는 동일한 호출 권한만 승계한다.
 * 호출·동작 승인과 실제 변이 시작 검사는 HostRuntime의 책임이다.
 */
final class ScopedUndoTokens {
    static final int MAX_PRIVATE_TOKEN_BYTES = 64 * 1024;
    static final int MAX_RECEIPT_BYTES = 64 * 1024;
    static final int MAX_RECORD_BYTES = 512 * 1024;
    static final int MAX_RECORDS = 4096;
    private static final Set<String> CLAIM_FIELDS = Set.of("tokenRecordId", "tokenRecordDigest",
            "sourceOperationId", "sourceStepId", "sourceInvocationId");
    private final Map<String, Entry> records = new HashMap<>();
    private final Map<SourceKey, String> sources = new HashMap<>();
    private final Set<String> claimed = new HashSet<>();

    synchronized ObjectNode capture(HostSession session, Invocation source,
                                    String undoActionId, ObjectNode privateToken) {
        Owner owner = owner(session, source);
        if (undoActionId == null || undoActionId.length() > 1024
                || !undoActionId.matches("[a-z0-9_.-]+:[a-z0-9_./-]+") || privateToken == null) {
            throw failure("UNDO_TOKEN_INVALID", "Provider undo material is invalid");
        }
        if (ContractJson.bytes(privateToken).length > MAX_PRIVATE_TOKEN_BYTES) {
            throw failure("UNDO_TOKEN_LIMIT", "Provider undo material exceeds the host byte limit");
        }
        ObjectNode token = privateToken.deepCopy();
        int privateTokenBytes = ContractJson.bytes(token).length;
        if (privateTokenBytes > MAX_PRIVATE_TOKEN_BYTES) {
            throw failure("UNDO_TOKEN_LIMIT", "Provider undo material exceeds the host byte limit");
        }
        SourceKey key = SourceKey.of(owner, source);
        if (sources.containsKey(key)) {
            throw failure("UNDO_TOKEN_CONFLICT", "An invocation already owns frozen undo material");
        }
        if (records.size() >= MAX_RECORDS) {
            throw failure("UNDO_TOKEN_LIMIT", "Host undo record capacity is exhausted");
        }
        String recordId = "undo-" + UUID.randomUUID();
        ObjectNode receipt = ContractJson.newObject();
        receipt.put("contractVersion", ContractJson.VERSION);
        receipt.put("tokenRecordId", recordId);
        receipt.put("principalRef", owner.principalRef());
        receipt.put("sessionEpoch", owner.epoch());
        receipt.put("gameInstanceId", owner.gameInstanceId());
        receipt.put("side", owner.side());
        receipt.put("playerId", owner.playerId().toString());
        receipt.put("bindingId", source.bindingId());
        receipt.put("sourceActionId", source.actionId());
        receipt.put("sourceActionDigest", source.actionDigest());
        receipt.put("sourceImplementationDigest", source.implementationDigest());
        receipt.put("sourceArgumentsDigest", source.argumentsDigest());
        receipt.put("sourceContextDigest", source.contextDigest());
        receipt.put("sourceOperationId", source.operationId());
        receipt.put("sourceStepId", source.stepId());
        receipt.put("sourceInvocationId", source.invocationId());
        receipt.put("undoActionId", undoActionId);
        receipt.set("sourceContext", owner.context().deepCopy());
        receipt.put("privateTokenSha256", ContractJson.digest(token));
        receipt.put("tokenRecordDigest", ContractJson.digest(receipt));
        ObjectNode sourceWire = source.wire();
        int receiptBytes = ContractJson.bytes(receipt).length;
        long recordBytes = (long) ContractJson.bytes(sourceWire).length
                + ContractJson.bytes(owner.context()).length + receiptBytes + privateTokenBytes;
        if (receiptBytes > MAX_RECEIPT_BYTES || recordBytes > MAX_RECORD_BYTES) {
            throw failure("UNDO_TOKEN_LIMIT", "Frozen undo material exceeds the host record byte limit");
        }
        Entry entry = new Entry(owner, sourceWire, undoActionId, token, receipt);
        records.put(recordId, entry);
        sources.put(key, recordId);
        return receipt.deepCopy();
    }

    /** 영수증 조회는 원래 호출의 모든 wire 값과 현재 설치된 권한을 다시 확인한다. */
    synchronized ObjectNode receipt(HostSession session, Invocation source) {
        Owner owner = owner(session, source);
        String id = sources.get(SourceKey.of(owner, source));
        if (id == null) return null;
        Entry entry = records.get(id);
        if (!entry.owner().equals(owner) || !entry.source().equals(source.wire())) {
            throw failure("RECOVERY_SCOPE_MISMATCH", "Undo material does not belong to this invocation");
        }
        verifyMaterial(entry);
        return entry.receipt().deepCopy();
    }

    /**
     * 콜백에 넘기기 전에 소비한다. 성공 여부가 불확실해도 다른 호출로 다시 사용할 수
     * 없으며, 같은 호출의 중복 처리는 HostRuntime의 호출 기록이 담당한다.
     */
    synchronized ObjectNode claim(HostSession current, Invocation recovery) {
        return claimWithSource(current, recovery).privateToken();
    }

    /** Private token and public provenance are obtained from the same atomic consumed entry. */
    synchronized ClaimedUndo claimWithSource(HostSession current, Invocation recovery) {
        Owner owner = owner(current, recovery);
        ObjectNode arguments = recovery.arguments();
        if (arguments.size() != CLAIM_FIELDS.size()) throw invalidClaim();
        for (String field : CLAIM_FIELDS) {
            JsonNode value = arguments.get(field);
            if (value == null || !value.isTextual() || value.textValue().isEmpty()) throw invalidClaim();
        }
        Entry entry = records.get(arguments.path("tokenRecordId").asText());
        if (entry == null) {
            throw failure("RECOVERY_EXPIRED", "Undo material is unavailable or already claimed");
        }
        verifyMaterial(entry);
        ObjectNode receipt = entry.receipt();
        if (!sameTargetOwner(entry.owner(), owner)
                || !entry.source().path("bindingId").asText().equals(recovery.bindingId())
                || !entry.undoActionId().equals(recovery.actionId())
                || !receipt.path("tokenRecordDigest").asText().equals(arguments.path("tokenRecordDigest").asText())
                || !receipt.path("sourceOperationId").asText().equals(arguments.path("sourceOperationId").asText())
                || !receipt.path("sourceStepId").asText().equals(arguments.path("sourceStepId").asText())
                || !receipt.path("sourceInvocationId").asText().equals(arguments.path("sourceInvocationId").asText())) {
            throw failure("RECOVERY_SCOPE_MISMATCH", "Undo material does not belong to this recovery invocation");
        }
        String id = receipt.path("tokenRecordId").asText();
        if (!claimed.add(id)) {
            throw failure("RECOVERY_EXPIRED", "Undo material is unavailable or already claimed");
        }
        return new ClaimedUndo(entry.privateToken(), entry.source(), entry.receipt());
    }

    record ClaimedUndo(ObjectNode privateToken, ObjectNode sourceInvocation, ObjectNode sourceReceipt) {
        ClaimedUndo {
            privateToken = privateToken.deepCopy(); sourceInvocation = sourceInvocation.deepCopy(); sourceReceipt = sourceReceipt.deepCopy();
        }
        @Override public ObjectNode privateToken() { return privateToken.deepCopy(); }
        @Override public ObjectNode sourceInvocation() { return sourceInvocation.deepCopy(); }
        @Override public ObjectNode sourceReceipt() { return sourceReceipt.deepCopy(); }
    }

    /** 호스트 generation 전체의 종료 때 호출한다. 개별 승인 세션 종료 때 지우지 않는다. */
    synchronized void clear() {
        records.clear(); sources.clear(); claimed.clear();
    }

    private static Owner owner(HostSession session, Invocation invocation) {
        session.checkOpen();
        ObjectNode context = invocation.context();
        if (session.playerId() == null || !session.context(invocation.contextId()).equals(context)
                || !session.principalRef().equals(context.path("principalRef").asText())
                || !session.epoch().equals(context.path("environment").path("sessionEpoch").asText())
                || !session.gameInstanceId().equals(context.path("environment").path("gameInstanceId").asText())
                || !session.side().equals(context.path("environment").path("side").asText())) {
            throw failure("RECOVERY_SCOPE_MISMATCH", "Undo material requires the exact installed invocation context");
        }
        return new Owner(session.principalRef(), session.epoch(), session.gameInstanceId(),
                session.side(), session.playerId(), context);
    }

    /**
     * 새 복구의 현재 정책 승인은 HostRuntime이 먼저 검사한다. claim에서만 정책 revision과
     * 그에 따라 달라지는 context digest를 제외하며, 원본 문맥과 공개 영수증은 바꾸지 않는다.
     */
    private static boolean sameTargetOwner(Owner source, Owner current) {
        if (!source.principalRef().equals(current.principalRef()) || !source.epoch().equals(current.epoch())
                || !source.gameInstanceId().equals(current.gameInstanceId()) || !source.side().equals(current.side())
                || !source.playerId().equals(current.playerId())) return false;
        ObjectNode originalTarget = source.context().deepCopy();
        ObjectNode currentTarget = current.context().deepCopy();
        originalTarget.remove("policyRevision"); originalTarget.remove("contextDigest");
        currentTarget.remove("policyRevision"); currentTarget.remove("contextDigest");
        return originalTarget.equals(currentTarget);
    }

    private static void verifyMaterial(Entry entry) {
        ObjectNode projection = entry.receipt().deepCopy();
        String digest = projection.remove("tokenRecordDigest").asText();
        if (!ContractJson.digest(projection).equals(digest)
                || !ContractJson.digest(entry.privateToken()).equals(entry.receipt().path("privateTokenSha256").asText())) {
            throw failure("RECOVERY_EXPIRED", "Frozen undo material failed its integrity check");
        }
    }

    private static ContractException invalidClaim() {
        return failure("RECOVERY_ARGUMENTS_INVALID", "Recovery requires the exact undo receipt references");
    }

    private static ContractException failure(String code, String message) {
        return new ContractException(code, message);
    }

    private record Owner(String principalRef, String epoch, String gameInstanceId,
                         String side, UUID playerId, ObjectNode context) { }
    private record SourceKey(String principalRef, String epoch, String gameInstanceId,
                             String side, String bindingId, String invocationId) {
        static SourceKey of(Owner owner, Invocation source) {
            return new SourceKey(owner.principalRef(), owner.epoch(), owner.gameInstanceId(),
                    owner.side(), source.bindingId(), source.invocationId());
        }
    }
    private record Entry(Owner owner, ObjectNode source, String undoActionId,
                         ObjectNode privateToken, ObjectNode receipt) { }
}
