package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 원본 예제는 undo role의 native 관측 wrapper를 제공하지 않아 순수 계약 경계 자료만 구성한다.
 * 등록 자료와 source facts는 작성된 단위 검사 입력이며 게임 실행·등록 관측·profile 검증 증거가 아니다.
 */
final class NativeUndoInspectionTest {
    private static final String HOST = "a".repeat(64);
    private static final String GENERATION = "31";
    private static final Instant OBSERVED_AT = Instant.parse("2026-10-14T00:00:00Z");
    private static final Set<String> CORE_FIELDS = Set.of("bindingId", "actionId", "selectedAction", "selectedActionDigest",
            "providerOrigin", "role", "registrationGeneration", "routes");
    private static final Set<String> WRAPPER_FIELDS = Set.of("registration", "contextId", "contextDigest", "environment",
            "runtimeSourceFactsDigest", "hostArtifactDigest", "registryGeneration", "observedFromTick", "observedToTick", "observedAt");

    @Test
    void nativeRoleObservationContainsExactlyTheClosedCoreAndWrapperFields() throws IOException {
        Inputs inputs = inputs();
        ObjectNode wrapper = role(inputs, 7, 8);
        assertEquals(10, wrapper.size()); assertEquals(WRAPPER_FIELDS, fields(wrapper));
        assertEquals(8, wrapper.path("registration").size());
        assertEquals(CORE_FIELDS, fields(ContractJson.object(wrapper.path("registration"))));
        assertEquals(inputs.registration(), wrapper.path("registration"));
        assertEquals(inputs.context().path("contextId"), wrapper.path("contextId"));
        assertEquals(inputs.context().path("contextDigest"), wrapper.path("contextDigest"));
        assertEquals(inputs.context().path("environment"), wrapper.path("environment"));
        assertEquals(HOST, wrapper.path("hostArtifactDigest").asText());
        assertEquals(GENERATION, wrapper.path("registryGeneration").asText());
        assertEquals("7", wrapper.path("observedFromTick").asText());
        assertEquals("8", wrapper.path("observedToTick").asText());
        assertEquals(OBSERVED_AT.toString(), wrapper.path("observedAt").asText());
        assertFalse(wrapper.has("verified")); assertFalse(wrapper.has("success"));
    }

    @Test
    void sourceFactsDigestExcludesOnlyTheTopLevelObservationTimestamp() throws IOException {
        Inputs inputs = inputs(); ObjectNode projection = inputs.facts().deepCopy(); projection.remove("observedAt");
        ObjectNode first = role(inputs, 7, 8);
        assertEquals(ContractJson.digest(projection), first.path("runtimeSourceFactsDigest").asText());
        ObjectNode changedTopTime = inputs.facts().deepCopy().put("observedAt", "2026-10-14T00:01:00Z");
        ObjectNode later = role(new Inputs(inputs.registration(), inputs.context(), changedTopTime), 7, 8);
        assertEquals(first.path("runtimeSourceFactsDigest"), later.path("runtimeSourceFactsDigest"));
        assertEquals("2026-10-14T00:00:00Z", inputs.facts().path("observedAt").asText());

        ObjectNode changedNestedTime = inputs.facts().deepCopy();
        changedNestedTime.withObject("runtimeGame").withObject("serverClassCodeSource")
                .put("observedAt", "2026-10-14T00:01:00Z");
        ObjectNode changedReason = inputs.facts().deepCopy();
        changedReason.withObject("runtimeGame").withObject("serverClassCodeSource").put("reason", "SOURCE_CHANGED_DURING_OBSERVATION");
        for (ObjectNode changed : new ObjectNode[] {changedNestedTime, changedReason}) {
            ObjectNode wrapper = role(new Inputs(inputs.registration(), inputs.context(), changed), 7, 8);
            assertNotEquals(first.path("runtimeSourceFactsDigest"), wrapper.path("runtimeSourceFactsDigest"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"sessionEpoch", "gameInstanceId", "worldId", "side", "kind"})
    void anyDifferentObservedEnvironmentIdentityRejectsTheRole(String identity) throws IOException {
        Inputs inputs = inputs(); inputs.facts().withObject("environment").put(identity, "different-observed-identity");
        assertEquals("STALE_CONTEXT", assertThrows(ContractException.class, () -> role(inputs, 7, 8)).code());
    }

    @Test
    void actualRegistryGenerationAndCurrentGenerationMustMatchIndependently() throws IOException {
        Inputs observedDrift = inputs(); observedDrift.facts().put("registryGeneration", "32");
        assertEquals("STALE_CONTEXT", assertThrows(ContractException.class, () -> role(observedDrift, 7, 8)).code());
        Inputs currentDrift = inputs();
        assertEquals("STALE_CONTEXT", assertThrows(ContractException.class, () -> NativeUndoInspection.role(
                currentDrift.registration(), currentDrift.context(), currentDrift.facts(), HOST, "32", 7, 8, OBSERVED_AT)).code());
    }

    @Test
    void negativeOrReversedObservationTicksAreRejected() throws IOException {
        Inputs inputs = inputs();
        for (long[] range : new long[][] {{-1, 0}, {-1, -1}, {0, -1}, {8, 7}}) {
            assertEquals("STALE_CONTEXT", assertThrows(ContractException.class,
                    () -> role(inputs, range[0], range[1])).code());
        }
        ObjectNode zero = role(inputs, 0, 0);
        assertEquals("0", zero.path("observedFromTick").asText()); assertEquals("0", zero.path("observedToTick").asText());
        ObjectNode maximum = role(inputs, Long.MAX_VALUE, Long.MAX_VALUE);
        assertEquals(Long.toString(Long.MAX_VALUE), maximum.path("observedToTick").asText());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not-a-hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
    void hostArtifactDigestMustBeAnExactLowercaseSha256(String digest) throws IOException {
        Inputs inputs = inputs();
        assertEquals("STALE_CONTEXT", assertThrows(ContractException.class, () -> NativeUndoInspection.role(
                inputs.registration(), inputs.context(), inputs.facts(), digest, GENERATION, 7, 8, OBSERVED_AT)).code());
    }

    @Test
    void registrationCoreCannotContainMissingOrCallerSuppliedAuthorityFields() throws IOException {
        for (String field : CORE_FIELDS) {
            Inputs missing = inputs(); missing.registration().remove(field);
            assertThrows(ContractException.class, () -> role(missing, 7, 8));
        }
        Inputs extra = inputs(); extra.registration().put("callerVerified", true);
        assertThrows(ContractException.class, () -> role(extra, 7, 8));
    }

    @Test
    void returnedWrapperAndCallerInputsAreIndependentDeepSnapshots() throws IOException {
        Inputs inputs = inputs(); ObjectNode registrationBefore = inputs.registration().deepCopy();
        ObjectNode contextBefore = inputs.context().deepCopy(); ObjectNode factsBefore = inputs.facts().deepCopy();
        ObjectNode wrapper = role(inputs, 7, 8); ObjectNode wrapperBefore = wrapper.deepCopy();
        assertEquals(registrationBefore, inputs.registration()); assertEquals(contextBefore, inputs.context());
        assertEquals(factsBefore, inputs.facts());

        wrapper.withObject("registration").withObject("selectedAction").put("title", "changed response only");
        wrapper.withObject("registration").withObject("providerOrigin").put("sourceId", "changed response only");
        wrapper.withObject("registration").withArray("routes").addObject().put("sourceActionId", "invented");
        wrapper.withObject("environment").put("sessionEpoch", "changed response only");
        assertEquals(registrationBefore, inputs.registration()); assertEquals(contextBefore, inputs.context());
        assertEquals(factsBefore, inputs.facts());

        ObjectNode second = role(inputs, 7, 8);
        inputs.registration().withObject("selectedAction").put("title", "changed caller only");
        inputs.context().withObject("environment").put("sessionEpoch", "changed caller only");
        inputs.facts().withObject("runtimeGame").withObject("serverClassCodeSource").put("reason", "changed caller only");
        assertEquals(wrapperBefore, second);
        assertEquals(contextBefore.path("contextDigest"), second.path("contextDigest"));
    }

    private static ObjectNode role(Inputs inputs, long fromTick, long toTick) {
        return NativeUndoInspection.role(inputs.registration(), inputs.context(), inputs.facts(), HOST, GENERATION,
                fromTick, toTick, OBSERVED_AT);
    }

    private record Inputs(ObjectNode registration, ObjectNode context, ObjectNode facts) { }

    private static Inputs inputs() throws IOException {
        ObjectNode context = ContractJson.object(fixture("invocation.json").path("context")).deepCopy();
        ObjectNode provider = fixture("provider-supported.json");
        ObjectNode selectedAction = ContractJson.object(provider.path("actions").get(0)).deepCopy();
        ObjectNode registration = ContractJson.newObject().put("bindingId", provider.path("bindingId").asText())
                .put("actionId", selectedAction.path("actionId").asText()).put("selectedActionDigest", ContractJson.digest(selectedAction))
                .put("role", "ordinary").put("registrationGeneration", "b".repeat(64));
        registration.set("selectedAction", selectedAction); registration.set("providerOrigin", provider.path("origin").deepCopy());
        registration.putArray("routes");
        ObjectNode facts = ContractJson.newObject().put("format", "mmmm.native.source-facts/1")
                .put("registryGeneration", GENERATION).put("observedAt", OBSERVED_AT.toString()).put("transformedClassBytes", "not_observed");
        facts.set("environment", context.path("environment").deepCopy());
        facts.putObject("runtimeGame").putObject("serverClassCodeSource").put("status", "unknown")
                .put("reason", "SOURCE_ROOT_NOT_ORDINARY_ARCHIVE").put("observedAt", OBSERVED_AT.toString()).putNull("sourceId");
        return new Inputs(registration, context, facts);
    }

    private static Set<String> fields(ObjectNode object) {
        Set<String> names = new HashSet<>(); object.fieldNames().forEachRemaining(names::add); return names;
    }

    private static ObjectNode fixture(String name) throws IOException {
        Path source = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(source)) {
            return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1)));
        }
    }
}
