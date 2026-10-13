package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.Set;

/** Platform checks for an authority-produced profile receipt. This does not create runtime evidence. */
final class NativeProfileAdmission {
    static final String DIGEST_RECIPE = "mmmm.runtime-source-facts-digest/1";
    private NativeProfileAdmission() { }

    static String sourceDigest(ObjectNode actualFacts) {
        ObjectNode projection = actualFacts.deepCopy(); projection.remove("observedAt");
        return ContractJson.digest(projection);
    }

    static void require(ContractJson contracts, ObjectNode evidence, ObjectNode actualHello,
                        ObjectNode actualFacts, String actualHostDigest, String actualGeneration) {
        HostDispatcher.exactFields(evidence, Set.of("profile", "runtimeSourceFactsDigest", "hostArtifactDigest", "registryGeneration"));
        ObjectNode profile = ContractJson.object(evidence.get("profile")); contracts.validate("VersionProfile", profile);
        if (!"runtime_verified".equals(profile.path("validationStatus").asText())
                || !"verified".equals(profile.path("writeSupport").asText())
                || !"java".equals(profile.path("edition").asText())
                || !actualHello.path("gameVersion").equals(profile.path("gameVersion"))
                || javaMajor(actualHello.path("javaMajor")) != javaMajor(profile.path("javaMajor"))
                || profile.path("evidenceResourceIds").isEmpty()
                || !actualHostDigest.equals(evidence.path("hostArtifactDigest").asText())
                || !actualGeneration.equals(evidence.path("registryGeneration").asText())
                || !sourceDigest(actualFacts).equals(evidence.path("runtimeSourceFactsDigest").asText())) throw denied();
        boolean observedLoader = false;
        String loaderId = actualHello.path("loader").path("id").asText();
        for (JsonNode loader : profile.path("testedLoaders")) observedLoader |= loaderId.equals(loader.asText());
        if (!observedLoader) throw denied();
        // The profile game artifact is distinct from the host implementation JAR.
        // Only a receipt for an original input game archive may support this equality.
        String gameDigest = profile.path("artifactSha256").asText(); boolean observedArtifact = false;
        for (JsonNode input : actualFacts.path("originalInputGameJars")) {
            observedArtifact |= "observed".equals(input.path("status").asText())
                    && "original_game_input_container".equals(input.path("scope").asText())
                    && gameDigest.equals(input.path("sha256").asText());
        }
        if (!observedArtifact || !actualHello.path("environment").equals(actualFacts.path("environment"))
                || !actualGeneration.equals(actualFacts.path("registryGeneration").asText())) throw denied();
        // Rights, complete pack identities, compiler pins and evidence authenticity are checked by
        // the Rust authority before this private receipt crosses the approved anonymous bridge.
        // Unknown observations remain in the digest; this helper never promotes them to known.
    }
    /** JSON Schema integer is mathematical: 25, 25.0 and 2.5e1 denote the same Int32. */
    private static int javaMajor(JsonNode value) {
        if (!value.isNumber() || !Double.isFinite(value.doubleValue())) throw denied();
        try { return value.decimalValue().toBigIntegerExact().intValueExact(); }
        catch (ArithmeticException exception) { throw denied(); }
    }
    private static ContractException denied() {
        return new ContractException("TARGET_PROFILE_UNVERIFIED", "Authority profile evidence does not match the current observed platform sources");
    }
}
