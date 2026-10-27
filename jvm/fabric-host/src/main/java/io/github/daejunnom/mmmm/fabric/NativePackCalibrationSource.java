package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;

/** Transports privately issued PACK observations; JSON cannot restore an actual run or a grant. */
final class NativePackCalibrationSource {
    static final String FORMAT = "mmmm.native.pack-calibration-source/1";
    static final String TARGET_IMAGES_FORMAT = "mmmm.native.pack-calibration-target-images/1";
    static final String READY_FORMAT = "mmmm.native.pack-calibration-ready/1";
    static final String ISSUER_UNAVAILABLE = NativeCalibrationSource.ISSUER_UNAVAILABLE;
    private static final int MAX_OBJECTIVE_BYTES = 256 * 1024;
    private final ContractJson contracts;

    NativePackCalibrationSource(ContractJson contracts) {
        this.contracts = Objects.requireNonNull(contracts);
    }

    @FunctionalInterface
    interface Issuer {
        NativePackCalibrationRun.CompletedPackRun lookup(ObjectNode installedContext, String originalInvocationId);
    }

    ObjectNode inspect(ObjectNode installedContext, ObjectNode actualSourceFacts, String actualHostArtifactDigest,
                       String actualRegistryGeneration, ObjectNode request, Invocation actualOriginalInvocation,
                       Issuer issuer, Runnable freshCheckpoint) {
        Objects.requireNonNull(freshCheckpoint);
        return NativeCalibrationFunctions.checked(() -> {
            validateRequest(request);
            if (issuer == null) throw failure(ISSUER_UNAVAILABLE);
            ObjectNode context = Objects.requireNonNull(installedContext).deepCopy();
            ObjectNode facts = Objects.requireNonNull(actualSourceFacts).deepCopy();
            Invocation original = Objects.requireNonNull(actualOriginalInvocation);
            ObjectNode originalContext = original.context();
            contracts.validate("ExecutionContext", context);
            contracts.validate("ExecutionContext", originalContext);
            contracts.validate("Invocation", original.wire());
            String factsDigest = NativeProfileAdmission.sourceDigest(facts);
            if (!ContractJson.contextDigest(context).equals(context.path("contextDigest").asText())
                    || !ContractJson.contextDigest(originalContext).equals(originalContext.path("contextDigest").asText())
                    || !samePairedScope(context, originalContext)
                    || !original.invocationId().equals(request.path("invocationId").asText())
                    || !ContractJson.digest(original.wire()).equals(request.path("invocationDigest").asText())
                    || !context.path("environment").equals(facts.path("environment"))
                    || !Objects.equals(actualRegistryGeneration, facts.path("registryGeneration").asText())
                    || !factsDigest.equals(request.path("expectedRuntimeSourceFactsDigest").asText())
                    || !Objects.equals(actualRegistryGeneration, request.path("expectedRegistryGeneration").asText())) throw stale();
            freshCheckpoint.run();
            NativePackCalibrationRun.CompletedPackRun actual = issuer.lookup(context.deepCopy(), original.invocationId());
            if (actual == null) throw failure(ISSUER_UNAVAILABLE);
            return NativeCalibrationFunctions.checked(() -> {
                ObjectNode response = actual.wire(freshCheckpoint);
                for (String field : Set.of("contextId", "contextDigest", "environment"))
                    if (!response.path(field).equals(originalContext.path(field))) throw stale();
                if (!FORMAT.equals(response.path("format").asText())
                        || !ContractJson.VERSION.equals(response.path("protocolVersion").asText())
                        || !factsDigest.equals(response.path("runtimeSourceFactsDigest").asText())
                        || !Objects.equals(actualHostArtifactDigest, response.path("hostArtifactDigest").asText())
                        || !Objects.equals(actualRegistryGeneration, response.path("registryGeneration").asText())
                        || !original.operationId().equals(response.path("operationId").asText())
                        || !original.stepId().equals(response.path("stepId").asText())
                        || !original.invocationId().equals(response.path("invocationId").asText())
                        || !ContractJson.digest(original.wire()).equals(response.path("invocationDigest").asText())
                        || !ContractJson.digest(original.wire()).equals(ContractJson.digest(actual.original().wire()))) throw stale();
                contracts.validate("ResourceRef", response.get("sourceZipResource"));
                bounded(response);
                return response;
            }, () -> {
                freshCheckpoint.run();
                if (issuer.lookup(context.deepCopy(), original.invocationId()) != actual) throw stale();
                freshCheckpoint.run();
            });
        }, freshCheckpoint);
    }

    /** Called only while the actual runner freezes its private completed object. */
    static ObjectNode encode(NativePackCalibrationRun.CompletedPackRun actual, Runnable checkpoint) {
        Objects.requireNonNull(actual);
        Objects.requireNonNull(checkpoint);
        return NativeCalibrationFunctions.checked(() -> {
            Invocation original = Objects.requireNonNull(actual.original());
            ObjectNode context = original.context();
            ObjectNode environment = Objects.requireNonNull(actual.environment()).deepCopy();
            if (!environment.equals(context.path("environment"))) throw stale();
            String sourceFactsDigest = digest(actual.runtimeSourceFactsDigest());
            String hostDigest = digest(actual.hostArtifactDigest());
            String generation = generation(actual.registryGeneration());
            String programDigest = digest(actual.programDigest());
            String bundleDigest = digest(actual.sourceBundleDigest());
            byte[] loadReceipt = NativeFunctionLoadObservation.requirePackReceipt(actual.loadReceipt(), 47);
            byte[] runReceipt = NativeFunctionLoadObservation.requirePackReceipt(actual.runReceipt(), 48);
            ObjectNode resource = Objects.requireNonNull(actual.sourceZipResource()).deepCopy();
            ObjectNode value = envelope(context, sourceFactsDigest, hostDigest, generation)
                    .put("format", FORMAT)
                    .put("operationId", original.operationId()).put("stepId", original.stepId())
                    .put("invocationId", original.invocationId()).put("invocationDigest", ContractJson.digest(original.wire()))
                    .put("programDigest", programDigest).put("sourceBundleDigest", bundleDigest)
                    .put("loadReceiptHex", HexFormat.of().formatHex(loadReceipt))
                    .put("runReceiptHex", HexFormat.of().formatHex(runReceipt))
                    .put("observedFromTick", tick(actual.from())).put("observedToTick", tick(actual.to()))
                    .put("observedAt", Objects.requireNonNull(actual.observedAt()));
            value.set("sourceZipResource", resource);
            bounded(value);
            return value;
        }, checkpoint);
    }

    /** A separate raw whole-objective observation, never a historical execution receipt. */
    static ObjectNode targetImages(NativePackCalibrationRun.IndependentObjectiveImage actual, Runnable checkpoint) {
        Objects.requireNonNull(actual);
        Objects.requireNonNull(checkpoint);
        return NativeCalibrationFunctions.checked(() -> {
            ObjectNode context = Objects.requireNonNull(actual.context()).deepCopy();
            byte[] raw = Objects.requireNonNull(actual.rawBytes());
            if (raw.length == 0 || raw.length > MAX_OBJECTIVE_BYTES) throw limit();
            if (!ContractJson.contextDigest(context).equals(context.path("contextDigest").asText())) throw stale();
            ObjectNode value = envelope(context, digest(actual.sourceFactsDigest()), digest(actual.hostDigest()), generation(actual.generation()))
                    .put("format", TARGET_IMAGES_FORMAT)
                    .put("observedFromTick", tick(actual.from())).put("observedToTick", tick(actual.to()))
                    .put("observedAt", Objects.requireNonNull(actual.observedAt()));
            value.putArray("targets").add(ContractJson.newObject()
                    .put("targetId", "calibration-objective-mcalpack")
                    .put("rawBytesHex", HexFormat.of().formatHex(raw)).put("rawSha256", ContractJson.sha256(raw)));
            value.set("commandObservation", commandObservation(actual.commandObservation()));
            bounded(value);
            return value;
        }, checkpoint);
    }

    static void validateTargetRequest(ObjectNode request) {
        var fields = Set.of("kind", "invocationId", "invocationDigest");
        requireFields(request, fields);
        if (!"pack_calibration_run_target_state".equals(request.path("kind").asText())) throw invalid();
        requireInvocation(request);
        bounded(request);
    }

    private static ObjectNode envelope(ObjectNode context, String sourceFactsDigest, String hostDigest, String generation) {
        ObjectNode value = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION)
                .put("contextId", context.path("contextId").asText())
                .put("contextDigest", context.path("contextDigest").asText())
                .put("runtimeSourceFactsDigest", sourceFactsDigest)
                .put("hostArtifactDigest", hostDigest).put("registryGeneration", generation);
        value.set("environment", context.path("environment").deepCopy());
        return value;
    }

    private static void validateRequest(ObjectNode request) {
        var fields = Set.of("kind", "invocationId", "invocationDigest", "expectedRuntimeSourceFactsDigest", "expectedRegistryGeneration");
        requireFields(request, fields);
        if (!"pack_calibration_run_source".equals(request.path("kind").asText())) throw invalid();
        requireInvocation(request);
        if (!request.path("expectedRuntimeSourceFactsDigest").isTextual()) throw invalid();
        digest(request.path("expectedRuntimeSourceFactsDigest").asText());
        if (!request.path("expectedRegistryGeneration").isTextual()) throw invalid();
        generation(request.path("expectedRegistryGeneration").asText());
        bounded(request);
    }

    private static void requireFields(ObjectNode request, Set<String> fields) {
        if (request == null || request.size() != fields.size()) throw invalid();
        request.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); });
    }

    private static ObjectNode commandObservation(ObjectNode actual) {
        var booleanFields = Set.of("commandReturnObserved", "singleCallbackObserved", "queueTerminalObserved",
                "actualTaskTerminalObserved", "terminationConfirmed", "furtherEffectsPossible");
        requireFields(actual, Set.of("commandReturnObserved", "singleCallbackObserved", "queueTerminalObserved",
                "actualTaskTerminalObserved", "continuationPending", "terminationConfirmed", "furtherEffectsPossible"));
        for (String field : booleanFields) if (!actual.path(field).isBoolean()) throw invalid();
        if (!actual.path("continuationPending").isBoolean() && !actual.path("continuationPending").isNull()) throw invalid();
        return actual.deepCopy();
    }

    private static void requireInvocation(ObjectNode request) {
        if (!request.path("invocationId").isTextual()
                || !request.path("invocationId").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")
                || !request.path("invocationDigest").isTextual()) throw invalid();
        digest(request.path("invocationDigest").asText());
    }

    /** Semantic request comparison only; the actual host route supplies current read authority. */
    private static boolean samePairedScope(ObjectNode current, ObjectNode original) {
        for (String field : Set.of("principalRef", "projectId", "dimension", "environment"))
            if (!current.path(field).equals(original.path(field))) return false;
        return includesObjective(current) && includesObjective(original);
    }

    private static boolean includesObjective(ObjectNode context) {
        var targets = context.path("scope").path("externalTargetIds");
        if (!targets.isArray()) throw invalid();
        boolean present = false;
        for (var target : targets) {
            if (!target.isTextual()) throw invalid();
            if ("calibration-objective-mcalpack".equals(target.textValue())) present = true;
        }
        return present;
    }

    private static String digest(String value) {
        if (value == null || !value.matches("[a-f0-9]{64}")) throw invalid();
        return value;
    }

    private static String generation(String value) {
        if (value == null || !value.matches("(0|[1-9][0-9]{0,19})")) throw invalid();
        return value;
    }

    private static String tick(long value) {
        if (value < 0) throw invalid();
        return Long.toString(value);
    }

    static void bounded(ObjectNode value) {
        NativeCalibrationRunFacts.bounded(value);
    }

    private static ContractException invalid() { return failure("CALIBRATION_RUN_SOURCE_INVALID"); }
    private static ContractException stale() { return failure("CALIBRATION_RUN_SOURCE_STALE"); }
    private static ContractException limit() { return failure("CALIBRATION_RUN_SOURCE_LIMIT"); }
    private static ContractException failure(String code) {
        return new ContractException(code, "Actual PACK observations are unavailable or differ from the current retained request");
    }
}
