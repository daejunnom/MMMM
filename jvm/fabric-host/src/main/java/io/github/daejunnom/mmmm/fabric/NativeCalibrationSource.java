package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.util.Objects;
import java.util.Set;

/** Looks up typed original actual-run facts. No JSON receipt can be restored into issuance. */
final class NativeCalibrationSource {
    static final String FORMAT = "mmmm.native.calibration-run-source/3";
    static final String ISSUER_UNAVAILABLE = "CALIBRATION_RUN_ISSUER_UNAVAILABLE";
    private final ContractJson contracts;
    NativeCalibrationSource(ContractJson contracts) { this.contracts = Objects.requireNonNull(contracts); }
    @FunctionalInterface interface Issuer {
        NativeCalibrationRunFacts lookup(ObjectNode installedContext, String originalInvocationId);
    }
    ObjectNode inspect(ObjectNode installedContext, ObjectNode actualSourceFacts, String actualHostArtifactDigest,
                       String actualRegistryGeneration, ObjectNode request, Invocation actualOriginalInvocation,
                       Issuer issuer, Runnable originalCheckpoint) {
        return NativeCalibrationFunctions.checked(() -> {
            validateRequest(request);
            if (issuer == null) throw failure(ISSUER_UNAVAILABLE);
            ObjectNode context = Objects.requireNonNull(installedContext).deepCopy();
            ObjectNode facts = Objects.requireNonNull(actualSourceFacts).deepCopy();
            Invocation original = Objects.requireNonNull(actualOriginalInvocation);
            contracts.validate("ExecutionContext", context); contracts.validate("Invocation", original.wire());
            String factsDigest = NativeProfileAdmission.sourceDigest(facts);
            if (!ContractJson.contextDigest(context).equals(context.path("contextDigest").asText())
                    || !ContractJson.digest(context).equals(ContractJson.digest(original.context()))
                    || !original.invocationId().equals(request.path("invocationId").asText())
                    || !ContractJson.digest(original.wire()).equals(request.path("invocationDigest").asText())
                    || !context.path("environment").equals(facts.path("environment"))
                    || !actualRegistryGeneration.equals(facts.path("registryGeneration").asText())
                    || !factsDigest.equals(request.path("expectedRuntimeSourceFactsDigest").asText())
                    || !actualRegistryGeneration.equals(request.path("expectedRegistryGeneration").asText())) throw failure("CALIBRATION_RUN_SOURCE_STALE");
            originalCheckpoint.run();
            NativeCalibrationRunFacts actual = issuer.lookup(context.deepCopy(), original.invocationId());
            if (actual == null) throw failure(ISSUER_UNAVAILABLE);
            return NativeCalibrationFunctions.checked(() -> {
                ObjectNode response = actual.wire(originalCheckpoint);
                for (String field : Set.of("contextId", "contextDigest", "environment"))
                    if (!response.path(field).equals(context.path(field))) throw failure("CALIBRATION_RUN_SOURCE_STALE");
                if (!factsDigest.equals(response.path("runtimeSourceFactsDigest").asText())
                        || !actualHostArtifactDigest.equals(response.path("hostArtifactDigest").asText())
                        || !actualRegistryGeneration.equals(response.path("registryGeneration").asText())
                        || !original.invocationId().equals(response.path("invocationId").asText())
                        || !ContractJson.digest(original.wire()).equals(response.path("invocationDigest").asText())) throw failure("CALIBRATION_RUN_SOURCE_STALE");
                NativeCalibrationRunFacts.bounded(response); return response;
            }, () -> {
                originalCheckpoint.run();
                if (issuer.lookup(context.deepCopy(), original.invocationId()) != actual) throw failure("CALIBRATION_RUN_SOURCE_STALE");
                originalCheckpoint.run();
            });
        }, originalCheckpoint);
    }
    private static void validateRequest(ObjectNode request) {
        var fields = Set.of("kind", "invocationId", "invocationDigest", "expectedRuntimeSourceFactsDigest", "expectedRegistryGeneration");
        if (request == null || request.size() != fields.size()) throw invalid();
        request.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); });
        if (!"calibration_run_source".equals(request.path("kind").asText())
                || !request.path("invocationId").isTextual() || !request.path("invocationId").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid();
        for (String name : Set.of("invocationDigest", "expectedRuntimeSourceFactsDigest"))
            if (!request.path(name).isTextual() || !request.path(name).asText().matches("[a-f0-9]{64}")) throw invalid();
        if (!request.path("expectedRegistryGeneration").isTextual()
                || !request.path("expectedRegistryGeneration").asText().matches("(0|[1-9][0-9]{0,19})")) throw invalid();
        NativeCalibrationRunFacts.bounded(request);
    }
    private static ContractException invalid() { return failure("CALIBRATION_RUN_SOURCE_INVALID"); }
    private static ContractException failure(String code) { return new ContractException(code, "Original actual native run facts are unavailable or differ from the current request"); }
}
