package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ActionHandler;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 원본 예시와 저장소 단독 검사는 실제 등록→호출→토큰 캡처→새 승인 복구의 연결을
 * 다루지 않는다. 기존 예시를 변형하며 게임 readback·Rust 원장·실제 승인 증거는 만들지 않는다.
 */
final class RuntimeUndoBoundaryTest {
    private static final String BINDING = "binding-fixture-01";
    private static final String PERMISSION = "diagnostic.write";
    private static final String SOURCE_ACTION = "fixture:write_text";
    private static final String UNDO_ACTION = "fixture:undo_text";
    private static final UUID PLAYER = UUID.fromString("da0135a6-0b66-4df4-a95a-1838b312e403");
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-13T11:59:00Z"), ZoneOffset.UTC);
    private static final List<String> RECEIPT_REFERENCES = List.of("tokenRecordId", "tokenRecordDigest",
            "sourceOperationId", "sourceStepId", "sourceInvocationId");
    private final ContractJson contracts = new ContractJson();

    @Test
    void approvedRecoveryUsesFrozenSourceMaterialAndIsConsumedBeforeAFailedCallback() throws IOException {
        QueueThread queue = new QueueThread(); TestAuthority authority = new TestAuthority();
        ObjectNode sourceAction = sourceAction(); ObjectNode undoAction = undoAction();
        Invocation source = source(sourceAction, "one", context());
        ObjectNode currentContext = source.context().put("policyRevision", "0".repeat(64));
        currentContext.put("contextDigest", ContractJson.contextDigest(currentContext));
        HostSession original = installed(source.context(), Set.of(PERMISSION));
        AtomicInteger sourceCalls = new AtomicInteger(); AtomicInteger recoveryCalls = new AtomicInteger();
        AtomicInteger fallbackCalls = new AtomicInteger();
        ObjectNode privateToken = ContractJson.newObject().put("beforeText", "private-original-fixture");
        ObjectNode frozenToken = privateToken.deepCopy();

        try (HostRuntime runtime = runtime(queue, authority)) {
            register(runtime, sourceAction, (invocation, local) -> {
                sourceCalls.incrementAndGet(); local.beginMutation();
                local.recordEffect(ContractJson.newObject().put("fixtureWrite", "source"));
                local.captureUndoToken(privateToken);
                privateToken.put("beforeText", "changed after capture");
                return CompletableFuture.completedFuture(echo(invocation));
            }, undoAction, new OptionalCallbacks(null, null, null, null, (invocation, token, local) -> {
                recoveryCalls.incrementAndGet();
                assertEquals(frozenToken, token);
                assertEquals(currentContext, local.executionContext());
                assertFalse(source.operationId().equals(invocation.operationId()));
                assertFalse(source.invocationId().equals(invocation.invocationId()));
                local.beginMutation(); local.recordEffect(ContractJson.newObject().put("fixtureWrite", "recovery"));
                token.put("beforeText", "changed callback copy");
                return CompletableFuture.failedFuture(new ContractException("TEST_RECOVERY_RESPONSE_LOST",
                        "Fixture failure after the recovery mutation boundary"));
            }), fallbackCalls);
            ProviderResult sourceResult = complete(queue, runtime.dispatch(original, source));
            assertEquals("complete", sourceResult.status()); assertEquals("recorded", sourceResult.effects());
            assertEquals(1, sourceCalls.get());
            ObjectNode sourceOperation = runtime.operation(original, source.invocationId());
            ObjectNode receipt = ContractJson.object(sourceOperation.get("undoTokenRecord")).deepCopy();
            assertNotNull(receipt); assertFalse(sourceOperation.toString().contains("private-original-fixture"));
            assertEquals(ContractJson.digest(frozenToken), receipt.path("privateTokenSha256").asText());
            ObjectNode projection = receipt.deepCopy();
            assertEquals(projection.remove("tokenRecordDigest").asText(), ContractJson.digest(projection));
            assertEquals(source.actionDigest(), receipt.path("sourceActionDigest").asText());
            assertEquals(source.implementationDigest(), receipt.path("sourceImplementationDigest").asText());
            assertEquals(source.context(), receipt.path("sourceContext"));
            assertEquals(source.contextDigest(), receipt.path("sourceContextDigest").asText());
            assertFalse(source.contextDigest().equals(currentContext.path("contextDigest").asText()));
            assertEquals(undoAction, runtime.undoRegistration(BINDING, SOURCE_ACTION).path("undoAction"));
            ObjectNode material = runtime.undoMaterial(original, source.context(), source.invocationId());
            assertEquals(4, material.size()); assertEquals(PLAYER.toString(), material.path("authenticatedPlayerId").asText());
            assertEquals(source.wire(), material.path("sourceInvocation")); assertEquals(receipt, material.path("receipt"));
            assertEquals(undoAction, material.path("registration").path("undoAction"));
            material.withObject("receipt").put("privateTokenSha256", "changed-copy");
            assertEquals(receipt, runtime.undoMaterial(original, source.context(), source.invocationId()).path("receipt"));
            assertCode("STALE_CONTEXT", () -> runtime.undoMaterial(original, currentContext, source.invocationId()));

            HostSession approved = installed(currentContext, Set.of(PERMISSION));
            assertCode("INVOCATION_UNKNOWN", () -> runtime.operation(approved, source.invocationId()));
            assertCode("INVOCATION_UNKNOWN", () -> runtime.undoMaterial(approved, currentContext, source.invocationId()));
            ObjectNode reroutedSourceWire = source.wire(); reroutedSourceWire.set("context", currentContext);
            Invocation reroutedSource = invocation(reroutedSourceWire);
            assertCode("SESSION_ROUTE_CHANGED", () -> runtime.dispatch(approved, reroutedSource));
            queue.drain(); assertEquals(1, sourceCalls.get());
            assertEquals(sourceResult.wire(), runtime.dispatch(original, source).toCompletableFuture().join().wire());
            assertEquals(receipt, runtime.operation(original, source.invocationId()).path("undoTokenRecord"));

            // The caller must retain the source receipt before closing its original job route.
            runtime.closeSession(original);
            assertCode("SESSION_EXPIRED", () -> runtime.operation(original, source.invocationId()));
            HostSession noPermission = installed(currentContext, Set.of());
            Invocation deniedPermission = recovery(source, undoAction, receipt, "denied-permission", currentContext);
            assertFailure("PERMISSION_DENIED", complete(queue, runtime.dispatch(noPermission, deniedPermission)));
            authority.revoked = true;
            Invocation revokedGrant = recovery(source, undoAction, receipt, "revoked-grant", currentContext);
            assertFailure("PERMISSION_DENIED", complete(queue, runtime.dispatch(approved, revokedGrant)));
            authority.revoked = false;
            Invocation deniedAdmission = recovery(source, undoAction, receipt, "denied-admission", currentContext);
            authority.denied.add(deniedAdmission.invocationId());
            assertFailure("TEST_PLAN_NOT_APPROVED", complete(queue, runtime.dispatch(approved, deniedAdmission)));
            List<Consumer<ObjectNode>> targetChanges = List.of(
                    context -> context.withObject("scope").withArray("resourceIds").add("other-resource"),
                    context -> context.put("selectionRef", "other-selection"),
                    context -> context.putArray("origin").add(1).add(64).add(0));
            for (int index = 0; index < targetChanges.size(); index++) {
                ObjectNode changedContext = currentContext.deepCopy(); targetChanges.get(index).accept(changedContext);
                changedContext.put("contextDigest", ContractJson.contextDigest(changedContext));
                HostSession otherContext = installed(changedContext, Set.of(PERMISSION));
                Invocation wrongContext = recovery(source, undoAction, receipt, "wrong-context-" + index, changedContext);
                assertFailure("RECOVERY_SCOPE_MISMATCH", complete(queue, runtime.dispatch(otherContext, wrongContext)));
            }
            assertEquals(0, recoveryCalls.get());

            Invocation recovery = recovery(source, undoAction, receipt, "approved", currentContext);
            ProviderResult failed = complete(queue, runtime.dispatch(approved, recovery));
            assertFailure("TEST_RECOVERY_RESPONSE_LOST", failed); assertEquals("recorded", failed.effects());
            assertEquals(1, recoveryCalls.get()); assertEquals(0, fallbackCalls.get());
            assertEquals(failed.wire(), runtime.dispatch(approved, recovery).toCompletableFuture().join().wire());
            assertEquals(1, recoveryCalls.get());
            Invocation secondClaim = recovery(source, undoAction, receipt, "second-claim", currentContext);
            assertFailure("RECOVERY_EXPIRED", complete(queue, runtime.dispatch(approved, secondClaim)));
            assertEquals(1, recoveryCalls.get()); assertEquals(0, fallbackCalls.get());
            assertFalse(runtime.operation(approved, recovery.invocationId()).toString().contains("private-original-fixture"));
        }
    }

    @Test
    void acceptedInvocationCannotMoveSessionRouteOrRebindArgumentsAndContextBeforeAWrite() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode sourceAction = sourceAction(); ObjectNode undoAction = undoAction();
        Invocation source = source(sourceAction, "route", context());
        HostSession original = installed(source.context(), Set.of(PERMISSION));
        AtomicInteger sourceCalls = new AtomicInteger(); AtomicInteger recoveryCalls = new AtomicInteger();
        try (HostRuntime runtime = runtime(queue, new TestAuthority())) {
            register(runtime, sourceAction, (invocation, local) -> {
                sourceCalls.incrementAndGet(); local.beginMutation();
                return CompletableFuture.completedFuture(echo(invocation));
            }, undoAction, new OptionalCallbacks(null, null, null, null, (invocation, token, local) -> {
                recoveryCalls.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation));
            }), new AtomicInteger());
            var accepted = runtime.dispatch(original, source);
            var duplicate = runtime.dispatch(original, source);
            HostSession rotated = installed(source.context(), Set.of(PERMISSION));
            assertCode("SESSION_ROUTE_CHANGED", () -> runtime.dispatch(rotated, source));
            ObjectNode changedWire = source.wire(); changedWire.withObject("arguments").put("text", "different input");
            Invocation changedArguments = invocation(changedWire);
            assertCode("IDEMPOTENCY_CONFLICT", () -> runtime.dispatch(original, changedArguments));
            assertCode("SESSION_ROUTE_CHANGED", () -> runtime.dispatch(rotated, changedArguments));
            ObjectNode changedContext = source.context().put("contextId", "route-other-context").put("anchor", "eyes");
            changedContext.put("contextDigest", ContractJson.contextDigest(changedContext));
            original.installContext(contracts, changedContext);
            HostSession otherContext = installed(changedContext, Set.of(PERMISSION));
            changedWire = source.wire(); changedWire.set("context", changedContext);
            Invocation changedContextInvocation = invocation(changedWire);
            assertCode("IDEMPOTENCY_CONFLICT", () -> runtime.dispatch(original, changedContextInvocation));
            assertCode("SESSION_ROUTE_CHANGED", () -> runtime.dispatch(otherContext, changedContextInvocation));
            assertEquals(0, sourceCalls.get()); assertEquals(0, recoveryCalls.get());
            queue.drain(); assertEquals(1, sourceCalls.get());
            assertEquals(accepted.toCompletableFuture().join().wire(), duplicate.toCompletableFuture().join().wire());
            assertCode("INVOCATION_UNKNOWN", () -> runtime.operation(rotated, source.invocationId()));
            runtime.closeSession(original);
            assertCode("SESSION_ROUTE_CHANGED", () -> runtime.dispatch(rotated, source));
            assertEquals(1, sourceCalls.get());
        }
    }

    @Test
    void closingTheGenerationExpiresCapturedMaterialWithoutCallingTheNewRecoveryHandler() throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode sourceAction = sourceAction(); ObjectNode undoAction = undoAction();
        Invocation source = source(sourceAction, "generation", context());
        HostSession original = installed(source.context(), Set.of(PERMISSION));
        AtomicInteger recoveryCalls = new AtomicInteger(); AtomicInteger fallbackCalls = new AtomicInteger();
        ObjectNode receipt;
        try (HostRuntime runtime = runtime(queue, new TestAuthority())) {
            register(runtime, sourceAction, (invocation, local) -> {
                local.beginMutation(); local.captureUndoToken(ContractJson.newObject().put("beforeText", "original"));
                return CompletableFuture.completedFuture(echo(invocation));
            }, undoAction, new OptionalCallbacks(null, null, null, null, (invocation, token, local) -> {
                recoveryCalls.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation));
            }), fallbackCalls);
            assertEquals("complete", complete(queue, runtime.dispatch(original, source)).status());
            receipt = ContractJson.object(runtime.operation(original, source.invocationId()).get("undoTokenRecord")).deepCopy();
        }
        assertTrue(original.closed());
        ObjectNode newContext = source.context();
        newContext.withObject("environment").put("sessionEpoch", "epoch-fixture-02");
        newContext.put("contextDigest", ContractJson.contextDigest(newContext));
        HostSession nextGeneration = installed(newContext, Set.of(PERMISSION));
        try (HostRuntime next = runtime(queue, new TestAuthority())) {
            register(next, sourceAction, (invocation, local) -> CompletableFuture.completedFuture(echo(invocation)),
                    undoAction, new OptionalCallbacks(null, null, null, null, (invocation, token, local) -> {
                        recoveryCalls.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation));
                    }), fallbackCalls);
            Invocation recovery = recovery(source, undoAction, receipt, "next-generation", newContext);
            assertFailure("RECOVERY_EXPIRED", complete(queue, next.dispatch(nextGeneration, recovery)));
            assertEquals(0, recoveryCalls.get()); assertEquals(0, fallbackCalls.get());
            // The next host generation owns a separate bounded invocation index.
            Invocation freshSource = source(sourceAction, "generation", newContext);
            assertEquals("complete", complete(queue, next.dispatch(nextGeneration, freshSource)).status());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void recoveryCallbackChecksTheActualCapturedTargetImmediatelyBeforeRestore(boolean manualDrift) throws IOException {
        QueueThread queue = new QueueThread(); ObjectNode sourceAction = sourceAction(); ObjectNode undoAction = undoAction();
        Invocation source = source(sourceAction, "mutable-target", context());
        HostSession original = installed(source.context(), Set.of(PERMISSION));
        String targetId = "fixture:mutable-text";
        String originalText = "initial fixture target";
        String manualText = "manual change after recovery intent";
        AtomicReference<String> target = new AtomicReference<>(originalText);
        Map<String, AtomicReference<String>> targets = Map.of(targetId, target);
        AtomicInteger recoveryCalls = new AtomicInteger(); AtomicInteger restores = new AtomicInteger();
        AtomicInteger fallbackCalls = new AtomicInteger();
        try (HostRuntime runtime = runtime(queue, new TestAuthority())) {
            register(runtime, sourceAction, (invocation, local) -> {
                String before = target.get(); local.beginMutation();
                target.set(invocation.arguments().path("text").asText());
                String actualAfter = target.get();
                ObjectNode token = ContractJson.newObject().put("targetId", targetId)
                        .put("beforeText", before).put("afterText", actualAfter);
                local.captureUndoToken(token);
                local.recordEffect(ContractJson.newObject().put("targetId", targetId)
                        .put("beforeText", before).put("afterText", actualAfter));
                return CompletableFuture.completedFuture(ProviderResult.complete(contracts,
                        ContractJson.newObject().put("text", actualAfter), "recorded"));
            }, undoAction, new OptionalCallbacks(null, null, null, null, (invocation, token, local) -> {
                recoveryCalls.incrementAndGet(); local.requireGameThread();
                assertEquals(originalText, token.path("beforeText").asText());
                assertEquals("MMMM", token.path("afterText").asText());
                AtomicReference<String> actualTarget = targets.get(token.path("targetId").asText());
                if (actualTarget == null) throw new ContractException("RECOVERY_CONFLICT", "Captured fixture target is unavailable");
                // Provider undo owns this target-specific guard; generic authority checks cannot infer it.
                if (!actualTarget.get().equals(token.path("afterText").asText())) {
                    throw new ContractException("RECOVERY_CONFLICT", "Captured fixture target changed after source apply");
                }
                local.beginMutation();
                actualTarget.set(token.path("beforeText").asText()); restores.incrementAndGet();
                local.recordEffect(ContractJson.newObject().put("targetId", targetId)
                        .put("beforeText", token.path("afterText").asText()).put("afterText", actualTarget.get()));
                return CompletableFuture.completedFuture(ProviderResult.complete(contracts,
                        ContractJson.newObject().put("text", actualTarget.get()), "recorded"));
            }), fallbackCalls);
            ProviderResult applied = complete(queue, runtime.dispatch(original, source));
            assertEquals("complete", applied.status()); assertEquals("MMMM", target.get());
            ObjectNode receipt = ContractJson.object(runtime.operation(original, source.invocationId()).get("undoTokenRecord")).deepCopy();
            ObjectNode currentContext = source.context().put("policyRevision", "0".repeat(64));
            currentContext.put("contextDigest", ContractJson.contextDigest(currentContext));
            HostSession approved = installed(currentContext, Set.of(PERMISSION));
            runtime.closeSession(original);
            Invocation recovery = recovery(source, undoAction, receipt, "mutable-target", currentContext);
            CompletionStage<ProviderResult> pending = runtime.dispatch(approved, recovery);
            assertEquals(0, recoveryCalls.get());
            if (manualDrift) target.set(manualText);
            ProviderResult result = complete(queue, pending);
            if (manualDrift) {
                assertFailure("RECOVERY_CONFLICT", result); assertEquals(manualText, target.get());
                assertEquals(0, restores.get());
                assertEquals(0, runtime.operation(approved, recovery.invocationId()).path("effectObservations").size());
            } else {
                assertEquals("complete", result.status()); assertEquals("recorded", result.effects());
                assertEquals(originalText, target.get()); assertEquals(1, restores.get());
                assertEquals(originalText, result.data().path("text").asText());
            }
            assertEquals(1, recoveryCalls.get()); assertEquals(0, fallbackCalls.get());
            assertEquals(result.wire(), runtime.dispatch(approved, recovery).toCompletableFuture().join().wire());
            Invocation repeatedClaim = recovery(source, undoAction, receipt, "mutable-target-again", currentContext);
            assertFailure("RECOVERY_EXPIRED", complete(queue, runtime.dispatch(approved, repeatedClaim)));
            assertEquals(1, recoveryCalls.get()); assertEquals(0, fallbackCalls.get());
            assertEquals(manualDrift ? manualText : originalText, target.get());
            assertEquals(manualDrift ? 0 : 1, restores.get());
        }
    }

    private HostRuntime runtime(QueueThread queue, TestAuthority authority) {
        return new HostRuntime(contracts, queue, authority, (binding, descriptor) -> {
            assertEquals(BINDING, binding);
        }, CLOCK);
    }

    private void register(HostRuntime runtime, ObjectNode sourceAction, ActionHandler sourceHandler,
                          ObjectNode undoAction, OptionalCallbacks undoCallbacks, AtomicInteger fallbackCalls) throws IOException {
        ObjectNode provider = fixture("provider-supported.json"); provider.putArray("actions");
        runtime.registerProvider(provider);
        runtime.register(BINDING, sourceAction, sourceHandler, OptionalCallbacks.none());
        runtime.register(BINDING, undoAction, (invocation, local) -> {
            fallbackCalls.incrementAndGet(); return CompletableFuture.completedFuture(echo(invocation));
        }, undoCallbacks);
        runtime.registerUndo(BINDING, SOURCE_ACTION, UNDO_ACTION);
    }

    private ObjectNode sourceAction() throws IOException {
        ObjectNode action = ContractJson.object(fixture("provider-supported.json").path("actions").get(0)).deepCopy();
        action.put("actionId", SOURCE_ACTION).put("planning", "unsupported").put("effect", "write").put("recovery", "provider_undo");
        action.putArray("requiredPermissions").add(PERMISSION);
        return action;
    }

    private ObjectNode undoAction() throws IOException {
        ObjectNode action = sourceAction().put("actionId", UNDO_ACTION).put("recovery", "none");
        ObjectNode input = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        ObjectNode properties = input.putObject("properties");
        var required = input.putArray("required");
        for (String field : RECEIPT_REFERENCES) {
            properties.set(field, ContractJson.newObject().put("type", "string").put("minLength", 1));
            required.add(field);
        }
        action.set("inputSchema", input); return action;
    }

    private ObjectNode context() throws IOException { return fixture("invocation.json").withObject("context").deepCopy(); }

    private Invocation source(ObjectNode action, String suffix, ObjectNode context) throws IOException {
        ObjectNode wire = fixture("invocation.json");
        wire.put("invocationId", "source-" + suffix).put("operationId", "source-operation-" + suffix)
                .put("stepId", "source-step-" + suffix).put("actionId", action.path("actionId").asText())
                .put("actionDigest", ContractJson.digest(action)).put("implementationDigest", action.path("implementationDigest").asText());
        wire.set("context", context.deepCopy()); return invocation(wire);
    }

    private Invocation recovery(Invocation source, ObjectNode action, ObjectNode receipt, String suffix, ObjectNode context) {
        ObjectNode wire = source.wire();
        wire.put("invocationId", "recovery-" + suffix).put("operationId", "recovery-operation-" + suffix)
                .put("stepId", "recovery-step-" + suffix).put("actionId", action.path("actionId").asText())
                .put("actionDigest", ContractJson.digest(action)).put("implementationDigest", action.path("implementationDigest").asText());
        ObjectNode arguments = ContractJson.newObject();
        for (String field : RECEIPT_REFERENCES) arguments.set(field, receipt.get(field).deepCopy());
        wire.set("arguments", arguments); wire.set("context", context.deepCopy()); return invocation(wire);
    }

    private Invocation invocation(ObjectNode wire) {
        ObjectNode context = wire.withObject("context"); context.put("contextDigest", ContractJson.contextDigest(context));
        wire.put("contextDigest", context.path("contextDigest").asText());
        wire.put("argumentsDigest", ContractJson.digest(wire.path("arguments")));
        return new Invocation(contracts, wire);
    }

    private HostSession installed(ObjectNode context, Set<String> permissions) {
        JsonNode environment = context.path("environment");
        HostSession session = new HostSession(context.path("principalRef").asText(), environment.path("sessionEpoch").asText(),
                environment.path("gameInstanceId").asText(), environment.path("side").asText(), PLAYER, permissions, true);
        session.installContext(contracts, context); return session;
    }

    private ProviderResult echo(Invocation invocation) {
        return ProviderResult.complete(contracts, ContractJson.newObject().put("text", invocation.arguments().path("text").asText("recovered")), "none");
    }

    private static ProviderResult complete(QueueThread queue, CompletionStage<ProviderResult> stage) {
        queue.drain(); return stage.toCompletableFuture().join();
    }

    private static void assertFailure(String code, ProviderResult result) {
        assertEquals("failed", result.status()); assertEquals(code, result.wire().path("diagnostics").get(0).path("code").asText());
    }

    private static void assertCode(String code, Runnable operation) {
        assertEquals(code, assertThrows(ContractException.class, operation::run).code());
    }

    private static ObjectNode fixture(String name) throws IOException {
        Path path = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(path)) {
            return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1)));
        }
    }

    private static final class TestAuthority implements HostAuthority {
        private final Set<String> denied = new HashSet<>();
        private boolean revoked;
        @Override public boolean ready() { return true; }
        @Override public ObjectNode hello() { return ContractJson.newObject(); }
        @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) {
            if (write && revoked) throw new ContractException("PERMISSION_DENIED", "Fixture current write permission revoked");
        }
        @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) { }
        @Override public void checkInvocation(HostSession session, Invocation invocation, boolean write) {
            if (denied.contains(invocation.invocationId())) throw new ContractException("TEST_PLAN_NOT_APPROVED", "Fixture invocation admission rejected");
        }
    }

    private static final class QueueThread implements GameThread {
        private final ArrayDeque<Runnable> queue = new ArrayDeque<>(); private boolean active;
        @Override public boolean isSameThread() { return active; }
        @Override public void execute(Runnable runnable) { queue.add(runnable); }
        void drain() { active = true; try { while (!queue.isEmpty()) queue.removeFirst().run(); } finally { active = false; } }
    }
}
