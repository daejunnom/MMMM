package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Pure issuer-boundary fixtures. These bytes and counters are never native run or profile evidence. */
final class NativeCalibrationSourceTest {
    private static final String HOST = "a".repeat(64), GENERATION = "31";
    private static final List<String> COMMANDS = List.of("scoreboard objectives add fixture dummy", "say 😀");
    private final ContractJson contracts = new ContractJson();
    private final NativeCalibrationSource source = new NativeCalibrationSource(contracts);

    @Test void absentIssuerRejectsBeforeSourceProofOrInvocationAccess() throws IOException {
        Inputs inputs = inputs();
        ContractException unavailable = assertThrows(ContractException.class, () -> source.inspect(null, null, null, null, inputs.request(), null, null));
        assertEquals("CALIBRATION_RUN_ISSUER_UNAVAILABLE", unavailable.code());
        AtomicInteger lookups = new AtomicInteger();
        assertEquals("CALIBRATION_RUN_ISSUER_UNAVAILABLE", assertThrows(ContractException.class,
                () -> inspect(inputs, (context, id) -> { lookups.incrementAndGet(); return null; })).code());
        assertEquals(1, lookups.get());
    }

    @Test void callerProofHashesCannotManufactureAnActualIssuerRecord() throws IOException {
        Inputs inputs = inputs(); inputs.request().put("programDigest", "b".repeat(64));
        inputs.request().put("readbackSourceDigest", "c".repeat(64));
        AtomicInteger lookups = new AtomicInteger();
        assertEquals("CALIBRATION_RUN_ISSUER_UNAVAILABLE", assertThrows(ContractException.class, () -> inspect(inputs,
                (context, id) -> { lookups.incrementAndGet(); assertEquals(inputs.invocation().invocationId(), id); assertEquals(inputs.context(), context); return null; })).code());
        assertEquals(1, lookups.get());
        assertEquals("CALIBRATION_RUN_SOURCE_MISMATCH", assertThrows(ContractException.class,
                () -> inspect(inputs, (context, id) -> issued(inputs.response()))).code());
    }

    @Test void staleInvocationContextAndCurrentPinsRejectBeforeLookup() throws IOException {
        for (String field : Set.of("invocationId", "invocationDigest", "expectedRuntimeSourceFactsDigest", "expectedRegistryGeneration")) {
            Inputs inputs = inputs(); inputs.request().put(field, field.equals("invocationId") ? "another-invocation" : field.equals("expectedRegistryGeneration") ? "32" : "f".repeat(64));
            AtomicInteger lookups = new AtomicInteger();
            assertEquals("CALIBRATION_RUN_SOURCE_STALE", assertThrows(ContractException.class,
                    () -> inspect(inputs, (context, id) -> { lookups.incrementAndGet(); return issued(inputs.response()); })).code());
            assertEquals(0, lookups.get());
        }
        Inputs inputs = inputs(); inputs.context().put("anchor", "eyes"); inputs.context().put("contextDigest", ContractJson.contextDigest(inputs.context()));
        AtomicInteger lookups = new AtomicInteger();
        assertThrows(ContractException.class, () -> inspect(inputs, (context, id) -> { lookups.incrementAndGet(); return issued(inputs.response()); })); assertEquals(0, lookups.get());
    }

    @Test void exactActualSnapshotPreservesZeroAndNegativeNativeReturnsWithoutSuccessClaims() throws IOException {
        Inputs inputs = inputs(); ObjectNode before = inputs.response().deepCopy(); ObjectNode result = inspect(inputs, (context, id) -> issued(inputs.response()));
        assertEquals(before, result); assertEquals(20, result.size()); assertEquals(5, first(result.withArray("commands")).size());
        assertEquals(0, first(result.withArray("commands")).path("nativeReturn").intValue());
        assertEquals(-1, result.path("commands").get(1).path("nativeReturn").intValue());
        assertEquals(COMMANDS.get(1).length(), result.path("commands").get(1).path("consumedUtf16").intValue());
        assertFalse(result.has("verified")); assertFalse(result.has("success")); assertFalse(result.toString().contains("say 😀"));
        assertEquals("mmmm.native.calibration-run-source/2", result.path("format").asText());
        // codec fixture는 두 ordinal의 반환 callback 부재를 그대로 보존한다.
        // 선택한 정상 case의 실제 반환 필수 조건은 Rust 정본 검사가 별도로 확인한다.
        for (int index = 0; index < COMMANDS.size(); index++) {
            Inputs nullable = inputs(); ContractJson.object(nullable.response().withArray("commands").get(index)).putNull("nativeReturn");
            ObjectNode preserved = inspect(nullable, (context, id) -> issued(nullable.response()));
            assertEquals(nullable.response(), preserved); assertTrue(preserved.withArray("commands").get(index).has("nativeReturn"));
            assertTrue(preserved.withArray("commands").get(index).get("nativeReturn").isNull());
        }
    }

    @Test void originalReferenceAndContextNumericRepresentationsShareCanonicalIdentity() throws IOException {
        Inputs inputs = inputs(); ObjectNode request = ContractJson.object(ContractJson.parse(ContractJson.bytes(inputs.request())));
        inputs.context().withArray("origin").set(0, com.fasterxml.jackson.databind.node.IntNode.valueOf(0));
        assertTrue(request.path("sourceResource").path("sizeBytes").isBigInteger());
        assertTrue(inputs.response().path("sourceResource").path("sizeBytes").isInt());
        assertEquals(inputs.response(), source.inspect(inputs.context(), inputs.facts(), HOST, GENERATION, request, inputs.invocation(), (context, id) -> issued(inputs.response())));
    }

    @Test void totalSourceRowsMatchTheRustRunEvidenceLimit() throws IOException {
        Inputs inputs = inputs(); List<String> originalCommands = java.util.Collections.nCopies(20, COMMANDS.get(0));
        ArrayNode sourceCommands = ContractJson.newObject().putArray("commands"); originalCommands.forEach(sourceCommands::add);
        inputs.request().put("commandsDigest", ContractJson.digest(sourceCommands)); inputs.response().put("commandsDigest", ContractJson.digest(sourceCommands));
        ObjectNode base = first(inputs.response().withArray("commands")).deepCopy();
        for (String group : List.of("parserSources", "handlerSources")) {
            ArrayNode rows = base.withArray(group); ObjectNode receipt = first(rows).deepCopy(); rows.removeAll();
            for (int index = 0; index < 26; index++) rows.add(receipt.deepCopy().put("className", "fixture.Source" + index));
        }
        ArrayNode commands = inputs.response().putArray("commands"); for (int index = 0; index < originalCommands.size(); index++) commands.add(base.deepCopy());
        assertEquals("CALIBRATION_RUN_SOURCE_LIMIT", assertThrows(ContractException.class,
                () -> inspect(inputs, (context, id) -> new NativeCalibrationSource.IssuedReceipt(inputs.response(), originalCommands))).code());
    }

    @Test void requestAndResponseAreClosedAndBounded() throws IOException {
        Inputs unknown = inputs(); unknown.request().put("callerVerified", true); AtomicInteger lookups = new AtomicInteger();
        assertThrows(ContractException.class, () -> inspect(unknown, (context, id) -> { lookups.incrementAndGet(); return issued(unknown.response()); })); assertEquals(0, lookups.get());
        Inputs large = inputs(); large.request().withObject("sourceResource").put("mediaType", "x".repeat(1024 * 1024));
        assertThrows(ContractException.class, () -> inspect(large, (context, id) -> issued(large.response())));
        Inputs legacy = inputs(); legacy.response().put("format", "mmmm.native.calibration-run-source/1");
        assertThrows(ContractException.class, () -> inspect(legacy, (context, id) -> issued(legacy.response())));
        for (String field : Set.of("callerVerified", "uri")) {
            Inputs inputs = inputs(); inputs.response().put(field, "invented");
            assertThrows(ContractException.class, () -> inspect(inputs, (context, id) -> issued(inputs.response())));
        }
    }

    @Test void issuedIdentityResourcesAndReceiptSourcesMustMatchCurrentActualPins() throws IOException {
        for (String field : Set.of("contextDigest", "runtimeSourceFactsDigest", "hostArtifactDigest", "registryGeneration", "invocationDigest", "programDigest", "commandsDigest", "readbackSourceDigest")) {
            Inputs inputs = inputs(); inputs.response().put(field, field.equals("registryGeneration") ? "32" : "f".repeat(64));
            assertThrows(ContractException.class, () -> inspect(inputs, (context, id) -> issued(inputs.response())));
        }
        Inputs resource = inputs(); resource.response().withObject("sourceResource").put("resourceId", "other-source");
        assertThrows(ContractException.class, () -> inspect(resource, (context, id) -> issued(resource.response())));
        for (int kind = 0; kind < 3; kind++) {
            Inputs inputs = inputs(); ObjectNode command = first(inputs.response().withArray("commands"));
            if (kind == 0) command.putArray("parserSources");
            else if (kind == 1) first(command.withArray("handlerSources")).put("generation", "30");
            else { ObjectNode receipt = first(command.withArray("parserSources")); receipt.put("status", "unavailable"); receipt.remove("definitionSha256"); }
            assertThrows(ContractException.class, () -> inspect(inputs, (context, id) -> issued(inputs.response())));
        }
    }

    @Test void originalCommandOrderDigestsFullUtf16AndIndexSemanticsAreRequired() throws IOException {
        for (int kind = 0; kind < 11; kind++) {
            Inputs inputs = inputs(); ObjectNode command = first(inputs.response().withArray("commands"));
            switch (kind) {
                case 0 -> command.put("commandDigest", "f".repeat(64));
                case 1 -> command.put("consumedUtf16", 0);
                case 2 -> command.put("nativeReturn", 1.0);
                case 3 -> inputs.response().put("commandStageIndex", 2);
                case 4 -> inputs.response().put("preseedEndIndex", 2);
                case 5 -> inputs.response().put("observedToTick", "6");
                case 6 -> command.remove("nativeReturn");
                case 7 -> command.put("nativeReturn", (long) Integer.MAX_VALUE + 1);
                case 8 -> command.put("nativeReturn", (long) Integer.MIN_VALUE - 1);
                case 9 -> command.put("nativeReturn", "0");
                default -> inputs.response().withArray("commands").remove(0);
            }
            assertThrows(ContractException.class, () -> inspect(inputs, (context, id) -> issued(inputs.response())));
        }
        Inputs inputs = inputs();
        assertThrows(ContractException.class, () -> inspect(inputs, (context, id) -> new NativeCalibrationSource.IssuedReceipt(inputs.response(), List.of(COMMANDS.get(1), COMMANDS.get(0)))));
        assertThrows(ContractException.class, () -> inspect(inputs, (context, id) -> new NativeCalibrationSource.IssuedReceipt(inputs.response(), List.of("x".repeat(16 * 1024 + 1)))));
    }

    @Test void issuerRecordLookupArgumentsAndReturnedResponseRemainImmutable() throws IOException {
        Inputs inputs = inputs(); List<String> commands = new ArrayList<>(COMMANDS);
        NativeCalibrationSource.IssuedReceipt issued = new NativeCalibrationSource.IssuedReceipt(inputs.response(), commands);
        commands.set(0, "invented"); inputs.response().put("hostArtifactDigest", "f".repeat(64)); issued.response().put("hostArtifactDigest", "f".repeat(64));
        String originalContext = inputs.context().toString(), originalFacts = inputs.facts().toString(), originalRequest = inputs.request().toString();
        ObjectNode result = inspect(inputs, (context, id) -> { context.put("contextDigest", "f".repeat(64)); return issued; });
        result.put("hostArtifactDigest", "f".repeat(64));
        assertEquals(HOST, issued.response().path("hostArtifactDigest").asText()); assertEquals(COMMANDS, issued.originalCommands());
        assertThrows(UnsupportedOperationException.class, () -> issued.originalCommands().add("invented"));
        assertEquals(originalContext, inputs.context().toString()); assertEquals(originalFacts, inputs.facts().toString()); assertEquals(originalRequest, inputs.request().toString());
    }

    private ObjectNode inspect(Inputs inputs, NativeCalibrationSource.Issuer issuer) { return source.inspect(inputs.context(), inputs.facts(), HOST, GENERATION, inputs.request(), inputs.invocation(), issuer); }
    private static NativeCalibrationSource.IssuedReceipt issued(ObjectNode response) { return new NativeCalibrationSource.IssuedReceipt(response, COMMANDS); }
    private record Inputs(Invocation invocation, ObjectNode context, ObjectNode facts, ObjectNode request, ObjectNode response) { }
    private Inputs inputs() throws IOException {
        Path path = Path.of("examples", "invocation.json"); if (!Files.isRegularFile(path)) path = Path.of("..", "..", "examples", "invocation.json");
        Invocation original = new Invocation(contracts, ContractJson.parse(Files.readAllBytes(path))); ObjectNode context = original.context();
        ObjectNode facts = ContractJson.newObject().put("registryGeneration", GENERATION).put("observedAt", "2026-10-14T00:00:00Z"); facts.set("environment", context.get("environment").deepCopy());
        ObjectNode resource = ContractJson.newObject().put("resourceId", "fixture-calibration-program").put("sha256", "b".repeat(64)).put("mediaType", "application/json").put("sizeBytes", 123);
        ArrayNode commandSources = ContractJson.newObject().putArray("commands"); COMMANDS.forEach(commandSources::add);
        ObjectNode request = ContractJson.newObject().put("kind", "calibration_run_source").put("invocationId", original.invocationId())
                .put("invocationDigest", ContractJson.digest(original.wire())).put("programDigest", "c".repeat(64)).put("commandsDigest", ContractJson.digest(commandSources))
                .put("readbackSourceDigest", "d".repeat(64)).put("expectedRuntimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(facts)).put("expectedRegistryGeneration", GENERATION);
        request.set("sourceResource", resource.deepCopy());
        ObjectNode response = ContractJson.newObject().put("format", NativeCalibrationSource.FORMAT).put("protocolVersion", ContractJson.VERSION)
                .put("contextId", original.contextId()).put("contextDigest", original.contextDigest()).put("runtimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(facts))
                .put("hostArtifactDigest", HOST).put("registryGeneration", GENERATION).put("invocationId", original.invocationId()).put("invocationDigest", ContractJson.digest(original.wire()))
                .put("programDigest", "c".repeat(64)).put("commandsDigest", ContractJson.digest(commandSources)).put("readbackSourceDigest", "d".repeat(64))
                .put("preseedEndIndex", 1).put("commandStageIndex", 1).put("observedFromTick", "7").put("observedToTick", "8").put("observedAt", "2026-10-14T00:00:00Z");
        response.set("environment", context.get("environment").deepCopy()); response.set("sourceResource", resource.deepCopy());
        ArrayNode commands = response.putArray("commands");
        for (int index = 0; index < COMMANDS.size(); index++) {
            ObjectNode command = ContractJson.newObject().put("commandDigest", ContractJson.digest(TextNode.valueOf(COMMANDS.get(index))))
                    .put("consumedUtf16", COMMANDS.get(index).length()).put("nativeReturn", index == 0 ? 0 : -1);
            command.set("parserSources", sourceReceipts("fixture.Parser")); command.set("handlerSources", sourceReceipts("fixture.Handler")); commands.add(command);
        }
        return new Inputs(original, context, facts, request, response);
    }
    private static ArrayNode sourceReceipts(String className) {
        ArrayNode sources = ContractJson.newObject().putArray("sources"); sources.add(ContractJson.newObject().put("className", className)
                .put("definitionSha256", "e".repeat(64)).put("containerSha256", "f".repeat(64)).put("sourceKind", "loaded_definition_bytes")
                .put("admissionEvidenceSha256", "a".repeat(64)).put("loaderId", "fixture-loader").put("generation", GENERATION)); return sources;
    }
    private static ObjectNode first(ArrayNode values) { return ContractJson.object(values.get(0)); }
}
