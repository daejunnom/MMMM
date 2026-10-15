package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Looks up original dispatch-issued calibration evidence; it cannot run or manufacture a calibration. */
final class NativeCalibrationSource {
    static final String FORMAT = "mmmm.native.calibration-run-source/2";
    static final String ISSUER_UNAVAILABLE = "CALIBRATION_RUN_ISSUER_UNAVAILABLE";
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int MAX_COMMAND_BYTES = 16 * 1024;
    private static final int MAX_COMMANDS = 256;
    private static final int MAX_SOURCES = 64;
    private static final int MAX_TOTAL_SOURCES = 1024;
    private static final Set<String> REQUEST_FIELDS = Set.of("kind", "invocationId", "invocationDigest", "programDigest",
            "sourceResource", "commandsDigest", "readbackSourceDigest", "expectedRuntimeSourceFactsDigest", "expectedRegistryGeneration");
    private static final Set<String> RESPONSE_FIELDS = Set.of("format", "protocolVersion", "environment", "contextId", "contextDigest",
            "runtimeSourceFactsDigest", "hostArtifactDigest", "registryGeneration", "invocationId", "invocationDigest", "programDigest",
            "sourceResource", "commandsDigest", "readbackSourceDigest", "preseedEndIndex", "commandStageIndex", "commands",
            "observedFromTick", "observedToTick", "observedAt");
    private static final Set<String> COMMAND_FIELDS = Set.of("commandDigest", "consumedUtf16", "nativeReturn", "parserSources", "handlerSources");
    private static final Set<String> SOURCE_FIELDS = Set.of("className", "definitionSha256", "containerSha256", "sourceKind",
            "admissionEvidenceSha256", "loaderId", "generation");
    private final ContractJson contracts;

    NativeCalibrationSource(ContractJson contracts) { this.contracts = Objects.requireNonNull(contracts); }

    /**
     * Installed read-only port for evidence retained by actual dispatch. Implementations must not
     * register an invocation, run commands, generate proof, or derive a receipt from caller hashes.
     * The host resolves the retained original Invocation and installed route before calling this seam.
     */
    @FunctionalInterface
    interface Issuer { IssuedReceipt lookup(ObjectNode installedContext, String originalInvocationId); }

    /**
     * Immutable actual issued receipt and private exact original command sources. The source list
     * permits full-consumption/digest validation and is never included in the remote response.
     * Construction by trusted issuer code is required; JSON validity alone is not issuance authority.
     * Program and independent-readback pins remain the original producer's sealed observations.
     */
    record IssuedReceipt(ObjectNode response, List<String> originalCommands) {
        IssuedReceipt {
            response = Objects.requireNonNull(response).deepCopy();
            originalCommands = List.copyOf(Objects.requireNonNull(originalCommands));
        }
        @Override public ObjectNode response() { return response.deepCopy(); }
    }

    ObjectNode inspect(ObjectNode installedContext, ObjectNode actualSourceFacts, String actualHostArtifactDigest,
                       String actualRegistryGeneration, ObjectNode request, Invocation actualOriginalInvocation, Issuer issuer) {
        ObjectNode input = Objects.requireNonNull(request).deepCopy(); validateRequest(input);
        // Missing production issuer is explicit and precedes source proof or any parser. No parser lives here.
        if (issuer == null) throw failure(ISSUER_UNAVAILABLE);
        ObjectNode context = Objects.requireNonNull(installedContext).deepCopy();
        ObjectNode facts = Objects.requireNonNull(actualSourceFacts).deepCopy();
        Invocation original = Objects.requireNonNull(actualOriginalInvocation);
        contracts.validate("ExecutionContext", context); contracts.validate("Invocation", original.wire());
        digest(actualHostArtifactDigest); generation(actualRegistryGeneration);
        String currentFactsDigest = NativeProfileAdmission.sourceDigest(facts);
        String originalDigest = ContractJson.digest(original.wire());
        if (!ContractJson.contextDigest(context).equals(text(context, "contextDigest"))
                || !ContractJson.digest(context).equals(ContractJson.digest(original.context())) || !text(input, "invocationId").equals(original.invocationId())
                || !text(input, "invocationDigest").equals(originalDigest)
                || !context.path("environment").equals(facts.path("environment"))
                || !actualRegistryGeneration.equals(text(facts, "registryGeneration"))
                || !currentFactsDigest.equals(text(input, "expectedRuntimeSourceFactsDigest"))
                || !actualRegistryGeneration.equals(text(input, "expectedRegistryGeneration"))) throw failure("CALIBRATION_RUN_SOURCE_STALE");
        // Public proof digests never reach lookup: only the actual installed route and retained identity.
        IssuedReceipt issued = issuer.lookup(context.deepCopy(), original.invocationId());
        if (issued == null) throw failure(ISSUER_UNAVAILABLE);
        ObjectNode response = issued.response();
        validateResponse(response, issued.originalCommands(), context, currentFactsDigest, actualHostArtifactDigest,
                actualRegistryGeneration, original, originalDigest, input);
        return response.deepCopy();
    }

    private void validateRequest(ObjectNode input) {
        exact(input, REQUEST_FIELDS); bounded(input);
        if (!"calibration_run_source".equals(text(input, "kind"))) throw invalid();
        id(text(input, "invocationId"));
        for (String field : List.of("invocationDigest", "programDigest", "commandsDigest", "readbackSourceDigest", "expectedRuntimeSourceFactsDigest")) digest(text(input, field));
        generation(text(input, "expectedRegistryGeneration")); resource(ContractJson.object(input.get("sourceResource")));
    }

    private void validateResponse(ObjectNode response, List<String> originals, ObjectNode context, String factsDigest,
                                  String hostDigest, String generation, Invocation original, String originalDigest, ObjectNode request) {
        exact(response, RESPONSE_FIELDS); bounded(response);
        if (!FORMAT.equals(text(response, "format")) || !ContractJson.VERSION.equals(text(response, "protocolVersion"))) throw invalid();
        if (!context.path("environment").equals(response.path("environment"))
                || !text(context, "contextId").equals(text(response, "contextId"))
                || !text(context, "contextDigest").equals(text(response, "contextDigest"))
                || !factsDigest.equals(text(response, "runtimeSourceFactsDigest"))
                || !hostDigest.equals(text(response, "hostArtifactDigest"))
                || !generation.equals(text(response, "registryGeneration"))
                || !original.invocationId().equals(text(response, "invocationId"))
                || !originalDigest.equals(text(response, "invocationDigest"))) throw failure("CALIBRATION_RUN_SOURCE_STALE");
        resource(ContractJson.object(response.get("sourceResource")));
        if (!ContractJson.digest(request.get("sourceResource")).equals(ContractJson.digest(response.get("sourceResource")))) throw failure("CALIBRATION_RUN_SOURCE_MISMATCH");
        for (String field : List.of("programDigest", "commandsDigest", "readbackSourceDigest")) {
            digest(text(response, field));
            if (!text(request, field).equals(text(response, field))) throw failure("CALIBRATION_RUN_SOURCE_MISMATCH");
        }
        if (originals.isEmpty() || originals.size() > MAX_COMMANDS) throw invalid();
        ArrayNode commands = array(response, "commands", 1, MAX_COMMANDS);
        if (commands.size() != originals.size()) throw invalid();
        ArrayNode exactSources = ContractJson.newObject().putArray("commands"); int bytes = 0;
        for (String source : originals) {
            int size = source.getBytes(StandardCharsets.UTF_8).length;
            if (source.isEmpty() || source.startsWith("/") || source.indexOf('\r') >= 0 || source.indexOf('\n') >= 0
                    || source.indexOf('\0') >= 0 || size > MAX_COMMAND_BYTES || (bytes += size) > MAX_BYTES) throw invalid();
            exactSources.add(source);
        }
        // ContractJson also rejects unpaired UTF-16; this is the original ordered source array recipe.
        if (!text(response, "commandsDigest").equals(ContractJson.digest(exactSources))) throw failure("CALIBRATION_RUN_SOURCE_MISMATCH");
        int stage = integer(response.get("commandStageIndex")), preseed = integer(response.get("preseedEndIndex"));
        // Stage is a zero-based inclusive index. Preseed is an exclusive prefix count.
        if (stage < 0 || stage >= commands.size() || preseed < 0 || preseed > stage) throw invalid();
        int sourceCount = 0;
        for (int index = 0; index < commands.size(); index++) {
            ObjectNode command = ContractJson.object(commands.get(index)); exact(command, COMMAND_FIELDS);
            String source = originals.get(index); digest(text(command, "commandDigest"));
            if (!ContractJson.digest(TextNode.valueOf(source)).equals(text(command, "commandDigest"))
                    || integer(command.get("consumedUtf16")) != source.length()) throw failure("CALIBRATION_RUN_SOURCE_MISMATCH");
            nullableInteger(command.get("nativeReturn"));
            ArrayNode parsers = array(command, "parserSources", 1, MAX_SOURCES), handlers = array(command, "handlerSources", 1, MAX_SOURCES);
            if ((sourceCount += parsers.size() + handlers.size()) > MAX_TOTAL_SOURCES) throw failure("CALIBRATION_RUN_SOURCE_LIMIT");
            sources(parsers, generation); sources(handlers, generation);
        }
        long fromTick = unsignedTick(text(response, "observedFromTick")), toTick = unsignedTick(text(response, "observedToTick"));
        if (fromTick > toTick) throw invalid();
        String observedAt = text(response, "observedAt");
        try { if (observedAt.length() > 64) throw invalid(); Instant.parse(observedAt); }
        catch (DateTimeParseException exception) { throw invalid(); }
        // No success, target-kind, numeric behavior or transformed-bytecode claim is inferred here.
    }

    private void resource(ObjectNode resource) {
        contracts.validate("ResourceRef", resource);
        if (text(resource, "mediaType").length() > 256 || !resource.path("sizeBytes").isIntegralNumber()) throw invalid();
    }
    private static void sources(ArrayNode sources, String generation) {
        Set<String> classes = new HashSet<>();
        for (JsonNode value : sources) {
            ObjectNode source = ContractJson.object(value); exact(source, SOURCE_FIELDS);
            String name = text(source, "className");
            if (name.length() > 512 || !name.matches("[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*")
                    || !classes.add(name) || !"loaded_definition_bytes".equals(text(source, "sourceKind"))
                    || !generation.equals(text(source, "generation"))
                    || !text(source, "loaderId").matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) throw invalid();
            for (String field : List.of("definitionSha256", "containerSha256", "admissionEvidenceSha256")) digest(text(source, field));
        }
    }
    private static void bounded(ObjectNode value) { if (ContractJson.bytes(value).length > MAX_BYTES) throw failure("CALIBRATION_RUN_SOURCE_LIMIT"); }
    private static long unsignedTick(String value) { if (!value.matches("(0|[1-9][0-9]{0,9})")) throw invalid(); try { long tick = Long.parseLong(value); if (tick > 0xffff_ffffL) throw invalid(); return tick; } catch (NumberFormatException exception) { throw invalid(); } }
    private static int integer(JsonNode value) { try { if (value == null || !value.isIntegralNumber()) throw invalid(); return value.bigIntegerValue().intValueExact(); } catch (ArithmeticException exception) { throw invalid(); } }
    private static void nullableInteger(JsonNode value) { if (value == null) throw invalid(); if (!value.isNull()) integer(value); }
    private static ArrayNode array(ObjectNode value, String field, int minimum, int maximum) { if (!(value.get(field) instanceof ArrayNode array) || array.size() < minimum || array.size() > maximum) throw invalid(); return array; }
    private static String text(ObjectNode value, String field) { if (!value.path(field).isTextual()) throw invalid(); return value.get(field).textValue(); }
    private static void digest(String value) { if (value == null || !value.matches("[a-f0-9]{64}")) throw invalid(); }
    private static void id(String value) { if (!value.matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid(); }
    private static void generation(String value) { if (value == null || !value.matches("(0|[1-9][0-9]{0,19})")) throw invalid(); }
    private static void exact(ObjectNode value, Set<String> fields) { if (value.size() != fields.size()) throw invalid(); value.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); }); }
    private static ContractException invalid() { return failure("CALIBRATION_RUN_SOURCE_INVALID"); }
    private static ContractException failure(String code) { return new ContractException(code, "The original dispatch-issued calibration source is unavailable or does not match the current retained identity"); }
}
