package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.time.Instant;
import java.util.Set;

/** Source-bound Registrar inspection; source receipts remain observation, never write authority. */
final class NativeUndoInspection {
    private NativeUndoInspection() { }

    static ObjectNode role(ObjectNode registration, ObjectNode context, ObjectNode actualFacts,
                           String hostArtifactDigest, String registryGeneration,
                           long fromTick, long toTick, Instant observedAt) {
        HostDispatcher.exactFields(registration, Set.of("bindingId", "actionId", "selectedAction", "selectedActionDigest",
                "providerOrigin", "role", "registrationGeneration", "routes"));
        if (hostArtifactDigest == null || registryGeneration == null || observedAt == null
                || !registryGeneration.matches("0|[1-9][0-9]{0,18}")
                || !"mmmm.native.source-facts/1".equals(actualFacts.path("format").asText())
                || !context.path("environment").equals(actualFacts.path("environment"))
                || !registryGeneration.equals(actualFacts.path("registryGeneration").asText())
                || !hostArtifactDigest.matches("[a-f0-9]{64}") || fromTick < 0 || toTick < fromTick) {
            throw new ContractException("STALE_CONTEXT", "Undo role source observation differs from the installed native generation");
        }
        ObjectNode wrapper = ContractJson.newObject(); wrapper.set("registration", registration.deepCopy());
        wrapper.put("contextId", context.path("contextId").asText()).put("contextDigest", context.path("contextDigest").asText());
        wrapper.set("environment", context.path("environment").deepCopy());
        wrapper.put("runtimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(actualFacts))
                .put("hostArtifactDigest", hostArtifactDigest).put("registryGeneration", registryGeneration)
                .put("observedFromTick", Long.toString(fromTick)).put("observedToTick", Long.toString(toTick))
                .put("observedAt", observedAt.toString());
        return wrapper;
    }
}
