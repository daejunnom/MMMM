package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 원본 예시는 실제 등록 callback과 복구 연결에 따른 역할 증명·binding 격리·등록 동결을
 * 다루지 않는다. 기존 예시를 변형하며 loader 출처 승인이나 게임 실행 증거는 만들지 않는다.
 */
final class UndoRoleBoundaryTest {
    private static final String BINDING = "binding-fixture-01";
    private static final String OTHER_BINDING = "binding-fixture-02";
    private static final String ORDINARY = "fixture:ordinary";
    private static final String SOURCE = "fixture:source";
    private static final String UNDO = "fixture:undo";
    private static final Set<String> ROLE_FIELDS = Set.of("bindingId", "actionId", "selectedAction",
            "selectedActionDigest", "providerOrigin", "role", "registrationGeneration", "routes");
    private static final Set<String> ROUTE_FIELDS = Set.of("sourceBindingId", "sourceAction",
            "undoBindingId", "undoAction", "providerOrigin");
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-13T11:59:00Z"), ZoneOffset.UTC);
    private final ContractJson contracts = new ContractJson();
    private final AtomicInteger dispatchCalls = new AtomicInteger();
    private final AtomicInteger recoveryCalls = new AtomicInteger();

    @Test
    void actualRegisteredRolesContainCompleteBindingDescriptorsOriginAndGenerationAndSealRegistration() throws IOException {
        ObjectNode provider = provider(BINDING, "fixture_provider");
        ObjectNode ordinary = ordinary(ORDINARY); ObjectNode source = source(SOURCE); ObjectNode undo = undo(UNDO);
        try (HostRuntime runtime = runtime()) {
            runtime.registerProvider(provider); register(runtime, BINDING, ordinary, false);
            register(runtime, BINDING, source, false); register(runtime, BINDING, undo, true);
            runtime.registerUndo(BINDING, SOURCE, UNDO);
            ObjectNode generation = ContractJson.newObject().put("inventoryRevision", runtime.inventory().path("inventoryRevision").asText());
            generation.putArray("undoRoutes").add(ContractJson.newObject().put("bindingId", BINDING)
                    .put("sourceActionId", SOURCE).put("sourceActionDigest", ContractJson.digest(source))
                    .put("undoActionId", UNDO).put("undoActionDigest", ContractJson.digest(undo)));
            String expectedGeneration = ContractJson.digest(generation);
            ObjectNode ordinaryRole = runtime.undoRole(BINDING, ORDINARY);
            ObjectNode sourceRole = runtime.undoRole(BINDING, SOURCE);
            ObjectNode undoRole = runtime.undoRole(BINDING, UNDO);
            assertRole(ordinaryRole, BINDING, ordinary, provider.path("origin"), "ordinary", 0);
            assertRole(sourceRole, BINDING, source, provider.path("origin"), "source", 1);
            assertRole(undoRole, BINDING, undo, provider.path("origin"), "recovery_only", 1);
            assertEquals(expectedGeneration, ordinaryRole.path("registrationGeneration").asText());
            assertEquals(expectedGeneration, sourceRole.path("registrationGeneration").asText());
            assertEquals(expectedGeneration, undoRole.path("registrationGeneration").asText());
            assertRoute(sourceRole.path("routes").get(0), BINDING, source, undo, provider.path("origin"));
            assertRoute(undoRole.path("routes").get(0), BINDING, source, undo, provider.path("origin"));
            assertCode("REGISTRATION_CLOSED", () -> runtime.registerProvider(provider(OTHER_BINDING, "other_provider")));
            assertCode("REGISTRATION_CLOSED", () -> register(runtime, BINDING, ordinary("fixture:late"), false));
            assertCode("REGISTRATION_CLOSED", () -> runtime.registerUndo(BINDING, SOURCE, UNDO));
            assertEquals(0, dispatchCalls.get()); assertEquals(0, recoveryCalls.get());
        }
    }

    @Test
    void identicalActionIdsInAnotherBindingCannotInheritSourceRecoveryRolesOrRoutes() throws IOException {
        ObjectNode firstProvider = provider(BINDING, "provider_a");
        ObjectNode secondProvider = provider(OTHER_BINDING, "provider_b");
        ObjectNode firstSource = source(SOURCE); ObjectNode firstUndo = undo(UNDO);
        ObjectNode secondSource = ordinary(SOURCE).put("implementationDigest", "1".repeat(64));
        ObjectNode secondUndo = ordinary(UNDO).put("implementationDigest", "2".repeat(64));
        try (HostRuntime runtime = runtime()) {
            runtime.registerProvider(firstProvider); runtime.registerProvider(secondProvider);
            register(runtime, BINDING, firstSource, false); register(runtime, BINDING, firstUndo, true);
            runtime.registerUndo(BINDING, SOURCE, UNDO);
            register(runtime, OTHER_BINDING, secondSource, false); register(runtime, OTHER_BINDING, secondUndo, false);
            ObjectNode sourceRole = runtime.undoRole(BINDING, SOURCE);
            ObjectNode undoRole = runtime.undoRole(BINDING, UNDO);
            assertRole(sourceRole, BINDING, firstSource, firstProvider.path("origin"), "source", 1);
            assertRole(undoRole, BINDING, firstUndo, firstProvider.path("origin"), "recovery_only", 1);
            assertRoute(undoRole.path("routes").get(0), BINDING, firstSource, firstUndo, firstProvider.path("origin"));
            ObjectNode otherSourceRole = runtime.undoRole(OTHER_BINDING, SOURCE);
            ObjectNode otherUndoRole = runtime.undoRole(OTHER_BINDING, UNDO);
            assertRole(otherSourceRole, OTHER_BINDING, secondSource, secondProvider.path("origin"), "ordinary", 0);
            assertRole(otherUndoRole, OTHER_BINDING, secondUndo, secondProvider.path("origin"), "ordinary", 0);
            assertNotEquals(sourceRole.path("selectedActionDigest"), otherSourceRole.path("selectedActionDigest"));
            assertEquals(sourceRole.path("registrationGeneration"), otherSourceRole.path("registrationGeneration"));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void unknownBindingOrActionIsRejectedWithoutSealingTheRegistrar(boolean unknownBinding) throws IOException {
        try (HostRuntime runtime = runtime()) {
            runtime.registerProvider(provider(BINDING, "fixture_provider"));
            register(runtime, BINDING, ordinary(ORDINARY), false);
            assertCode("ACTION_UNKNOWN", () -> runtime.undoRole(unknownBinding ? OTHER_BINDING : BINDING,
                    unknownBinding ? ORDINARY : "fixture:unregistered"));
            ObjectNode added = ordinary("fixture:added_after_unknown"); register(runtime, BINDING, added, false);
            assertRole(runtime.undoRole(BINDING, added.path("actionId").asText()), BINDING, added,
                    provider(BINDING, "fixture_provider").path("origin"), "ordinary", 0);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void unlinkedSourceOrRecoveryCallbackCannotBecomeOrdinaryAndMayBeExplicitlyLinked(boolean recoveryOnly) throws IOException {
        ObjectNode source = source(SOURCE); ObjectNode undo = undo(UNDO);
        try (HostRuntime runtime = runtime()) {
            ObjectNode provider = provider(BINDING, "fixture_provider"); runtime.registerProvider(provider);
            register(runtime, BINDING, ordinary(ORDINARY), false);
            register(runtime, BINDING, recoveryOnly ? undo : source, recoveryOnly);
            assertCode("RECOVERY_UNSUPPORTED", () -> runtime.undoRole(BINDING, ORDINARY));
            assertCode("RECOVERY_UNSUPPORTED", () -> runtime.undoRole(BINDING, recoveryOnly ? UNDO : SOURCE));
            register(runtime, BINDING, recoveryOnly ? source : undo, !recoveryOnly);
            runtime.registerUndo(BINDING, SOURCE, UNDO);
            assertRole(runtime.undoRole(BINDING, recoveryOnly ? UNDO : SOURCE), BINDING,
                    recoveryOnly ? undo : source, provider.path("origin"), recoveryOnly ? "recovery_only" : "source", 1);
            assertEquals(0, dispatchCalls.get()); assertEquals(0, recoveryCalls.get());
        }
    }

    @Test
    void roleAndRouteSnapshotsCannotModifyRegisteredDescriptorsOriginsOrGeneration() throws IOException {
        ObjectNode provider = provider(BINDING, "fixture_provider");
        ObjectNode source = source(SOURCE); ObjectNode undo = undo(UNDO);
        ObjectNode originalSource = source.deepCopy(); ObjectNode originalUndo = undo.deepCopy();
        ObjectNode originalOrigin = ContractJson.object(provider.path("origin")).deepCopy();
        try (HostRuntime runtime = runtime()) {
            runtime.registerProvider(provider); register(runtime, BINDING, source, false); register(runtime, BINDING, undo, true);
            runtime.registerUndo(BINDING, SOURCE, UNDO);
            ObjectNode first = runtime.undoRole(BINDING, SOURCE); ObjectNode originalRole = first.deepCopy();
            provider.withObject("origin").put("sourceId", "caller_changed_provider");
            source.put("title", "caller changed source"); undo.put("title", "caller changed undo");
            first.withObject("selectedAction").put("title", "changed selected snapshot");
            first.withObject("providerOrigin").put("sourceId", "changed selected origin");
            ObjectNode route = ContractJson.object(first.path("routes").get(0));
            route.withObject("sourceAction").withObject("inputSchema").put("additionalProperties", true);
            route.withObject("undoAction").put("implementationDigest", "0".repeat(64));
            route.withObject("providerOrigin").put("sourceId", "changed route origin");
            first.put("role", "ordinary").put("registrationGeneration", "0".repeat(64)); first.putArray("routes");
            assertEquals(originalRole, runtime.undoRole(BINDING, SOURCE));
            ObjectNode undoRole = runtime.undoRole(BINDING, UNDO);
            assertRole(undoRole, BINDING, originalUndo, originalOrigin, "recovery_only", 1);
            assertRoute(undoRole.path("routes").get(0), BINDING, originalSource, originalUndo, originalOrigin);
            assertEquals(originalRole.path("registrationGeneration"), undoRole.path("registrationGeneration"));
            assertEquals(originalSource, runtime.describe(BINDING, SOURCE));
            assertEquals(originalUndo, runtime.describe(BINDING, UNDO));
        }
    }

    @Test
    void generationChangesWhenActualRegisteredProviderOriginChanges() throws IOException {
        ObjectNode ordinary = ordinary(ORDINARY);
        try (HostRuntime first = runtime(); HostRuntime second = runtime()) {
            first.registerProvider(provider(BINDING, "provider_a")); second.registerProvider(provider(BINDING, "provider_b"));
            register(first, BINDING, ordinary, false); register(second, BINDING, ordinary, false);
            ObjectNode firstRole = first.undoRole(BINDING, ORDINARY); ObjectNode secondRole = second.undoRole(BINDING, ORDINARY);
            assertEquals(firstRole.path("selectedActionDigest"), secondRole.path("selectedActionDigest"));
            assertNotEquals(firstRole.path("providerOrigin"), secondRole.path("providerOrigin"));
            assertNotEquals(firstRole.path("registrationGeneration"), secondRole.path("registrationGeneration"));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {64, 65})
    void selectedRecoveryRoutesHaveAFiniteLimitWithoutPartialResultsOrPrematureSealing(int sourceCount) throws IOException {
        ObjectNode provider = provider(BINDING, "fixture_provider"); ObjectNode undo = undo(UNDO);
        try (HostRuntime runtime = runtime()) {
            runtime.registerProvider(provider); register(runtime, BINDING, undo, true);
            for (int index = 0; index < sourceCount; index++) {
                String id = "fixture:source_" + String.format(java.util.Locale.ROOT, "%02d", index);
                register(runtime, BINDING, source(id), false); runtime.registerUndo(BINDING, id, UNDO);
            }
            if (sourceCount == 64) {
                ObjectNode generation = ContractJson.newObject().put("inventoryRevision", runtime.inventory().path("inventoryRevision").asText());
                var pins = generation.putArray("undoRoutes");
                for (int index = 0; index < sourceCount; index++) {
                    String id = "fixture:source_" + String.format(java.util.Locale.ROOT, "%02d", index);
                    pins.add(ContractJson.newObject().put("bindingId", BINDING).put("sourceActionId", id)
                            .put("sourceActionDigest", ContractJson.digest(source(id))).put("undoActionId", UNDO)
                            .put("undoActionDigest", ContractJson.digest(undo)));
                }
                ObjectNode role = runtime.undoRole(BINDING, UNDO);
                assertRole(role, BINDING, undo, provider.path("origin"), "recovery_only", 64);
                assertEquals(ContractJson.digest(generation), role.path("registrationGeneration").asText());
                assertTrue(ContractJson.bytes(role).length <= HostRuntime.MAX_RESULT_BYTES);
                Set<String> sources = new HashSet<>();
                for (JsonNode route : role.path("routes")) {
                    String id = route.path("sourceAction").path("actionId").asText();
                    assertTrue(sources.add(id)); assertRoute(route, BINDING, source(id), undo, provider.path("origin"));
                }
                assertEquals(64, sources.size());
            } else {
                assertCode("INPUT_LIMIT", () -> runtime.undoRole(BINDING, UNDO));
                ObjectNode late = ordinary("fixture:after_route_limit"); register(runtime, BINDING, late, false);
                assertRole(runtime.undoRole(BINDING, late.path("actionId").asText()), BINDING, late,
                        provider.path("origin"), "ordinary", 0);
            }
            assertEquals(0, dispatchCalls.get()); assertEquals(0, recoveryCalls.get());
        }
    }

    @Test
    void fullDescriptorRoleBytesAreBoundedWithoutSealingAFailedQuery() throws IOException {
        String largeSummary = "x".repeat(56 * 1024);
        ObjectNode firstSource = source("fixture:large_source_a").put("summary", largeSummary);
        ObjectNode secondSource = source("fixture:large_source_b").put("summary", largeSummary);
        ObjectNode largeUndo = undo(UNDO).put("summary", largeSummary);
        assertTrue(ContractJson.bytes(firstSource).length < 64 * 1024);
        assertTrue(ContractJson.bytes(largeUndo).length < 64 * 1024);
        try (HostRuntime runtime = runtime()) {
            ObjectNode provider = provider(BINDING, "fixture_provider"); runtime.registerProvider(provider);
            register(runtime, BINDING, firstSource, false); register(runtime, BINDING, secondSource, false);
            register(runtime, BINDING, largeUndo, true);
            runtime.registerUndo(BINDING, firstSource.path("actionId").asText(), UNDO);
            runtime.registerUndo(BINDING, secondSource.path("actionId").asText(), UNDO);
            assertCode("INPUT_LIMIT", () -> runtime.undoRole(BINDING, UNDO));
            ObjectNode late = ordinary("fixture:after_byte_limit"); register(runtime, BINDING, late, false);
            assertRole(runtime.undoRole(BINDING, late.path("actionId").asText()), BINDING, late,
                    provider.path("origin"), "ordinary", 0);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"failure", "null", "oversize", "register", "reenter"})
    void failedPlatformAttestationDoesNotSealAnOtherwiseValidRole(String outcome) throws IOException {
        ObjectNode provider = provider(BINDING, "fixture_provider");
        ObjectNode duringAttestation = ordinary("fixture:during_attestation");
        try (HostRuntime runtime = runtime()) {
            runtime.registerProvider(provider); register(runtime, BINDING, ordinary(ORDINARY), false);
            String expected = "failure".equals(outcome) ? "TEST_SOURCE_FACTS_FAILED"
                    : Set.of("register", "reenter").contains(outcome) ? "REGISTRATION_CLOSED" : "INPUT_LIMIT";
            assertCode(expected, () ->
                    runtime.undoRole(BINDING, ORDINARY, value -> {
                        if ("failure".equals(outcome)) throw new ContractException("TEST_SOURCE_FACTS_FAILED", "Fixture platform attestation failed");
                        if ("null".equals(outcome)) return null;
                        if ("register".equals(outcome)) register(runtime, BINDING, duringAttestation, false);
                        if ("reenter".equals(outcome)) return runtime.undoRole(BINDING, ORDINARY);
                        return value.put("attestationBytes", "x".repeat(HostRuntime.MAX_RESULT_BYTES));
                    }));
            ObjectNode late = ordinary("fixture:after_attestation_failure"); register(runtime, BINDING, late, false);
            ObjectNode verified = runtime.undoRole(BINDING, late.path("actionId").asText(), value -> value);
            assertRole(verified, BINDING, late, provider.path("origin"), "ordinary", 0);
            assertCode("REGISTRATION_CLOSED", () -> register(runtime, BINDING, ordinary("fixture:after_attestation_success"), false));
            assertEquals(0, dispatchCalls.get()); assertEquals(0, recoveryCalls.get());
        }
    }

    private HostRuntime runtime() {
        GameThread thread = new GameThread() {
            @Override public boolean isSameThread() { return false; }
            @Override public void execute(Runnable runnable) { throw new AssertionError("Role inspection must not execute a provider"); }
        };
        HostAuthority authority = new HostAuthority() {
            @Override public boolean ready() { return true; }
            @Override public ObjectNode hello() { return ContractJson.newObject(); }
            @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) {
                throw new AssertionError("Role inspection must not invoke a native mutation authority");
            }
            @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) {
                throw new AssertionError("Role inspection must not inspect a target");
            }
        };
        return new HostRuntime(contracts, thread, authority, (binding, descriptor) -> { }, CLOCK);
    }

    private void register(HostRuntime runtime, String binding, ObjectNode descriptor, boolean recovery) {
        OptionalCallbacks callbacks = recovery ? new OptionalCallbacks(null, null, null, null, (invocation, token, local) -> {
            recoveryCalls.incrementAndGet(); return CompletableFuture.completedFuture(
                    ProviderResult.complete(contracts, ContractJson.newObject().put("text", "recovered"), "none"));
        }) : OptionalCallbacks.none();
        runtime.register(binding, descriptor, (invocation, local) -> {
            dispatchCalls.incrementAndGet(); return CompletableFuture.completedFuture(
                    ProviderResult.complete(contracts, ContractJson.newObject().put("text", "fixture"), "none"));
        }, callbacks);
    }

    private ObjectNode provider(String binding, String sourceId) throws IOException {
        ObjectNode provider = fixture("provider-supported.json").put("bindingId", binding);
        provider.putArray("actions"); provider.withObject("origin").put("sourceId", sourceId); return provider;
    }

    private ObjectNode ordinary(String id) throws IOException {
        return ContractJson.object(fixture("provider-supported.json").path("actions").get(0)).deepCopy()
                .put("actionId", id).put("planning", "unsupported");
    }

    private ObjectNode source(String id) throws IOException {
        return ordinary(id).put("effect", "write").put("recovery", "provider_undo");
    }

    private ObjectNode undo(String id) throws IOException {
        ObjectNode action = ordinary(id).put("effect", "write");
        ObjectNode input = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        ObjectNode properties = input.putObject("properties"); var required = input.putArray("required");
        for (String field : List.of("tokenRecordId", "tokenRecordDigest", "sourceOperationId", "sourceStepId", "sourceInvocationId")) {
            properties.set(field, ContractJson.newObject().put("type", "string").put("minLength", 1)); required.add(field);
        }
        action.set("inputSchema", input); return action;
    }

    private static void assertRole(ObjectNode result, String binding, ObjectNode selected, JsonNode origin, String role, int routes) {
        assertEquals(ROLE_FIELDS, fields(result)); assertEquals(binding, result.path("bindingId").asText());
        assertEquals(selected.path("actionId").asText(), result.path("actionId").asText());
        assertEquals(selected, result.path("selectedAction")); assertEquals(ContractJson.digest(selected), result.path("selectedActionDigest").asText());
        assertEquals(origin, result.path("providerOrigin")); assertEquals(role, result.path("role").asText());
        assertEquals(routes, result.path("routes").size()); assertTrue(result.path("registrationGeneration").asText().matches("[a-f0-9]{64}"));
    }

    private static void assertRoute(JsonNode value, String binding, ObjectNode source, ObjectNode undo, JsonNode origin) {
        ObjectNode route = ContractJson.object(value); assertEquals(ROUTE_FIELDS, fields(route));
        assertEquals(binding, route.path("sourceBindingId").asText()); assertEquals(binding, route.path("undoBindingId").asText());
        assertEquals(source, route.path("sourceAction")); assertEquals(undo, route.path("undoAction"));
        assertEquals(origin, route.path("providerOrigin"));
    }

    private static Set<String> fields(ObjectNode value) {
        Set<String> fields = new HashSet<>(); value.fieldNames().forEachRemaining(fields::add); return fields;
    }

    private static void assertCode(String code, ThrowingAction action) {
        assertEquals(code, assertThrows(ContractException.class, action::run).code());
    }

    @FunctionalInterface private interface ThrowingAction { void run() throws IOException; }

    private static ObjectNode fixture(String name) throws IOException {
        Path path = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(path)) {
            return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1)));
        }
    }
}
