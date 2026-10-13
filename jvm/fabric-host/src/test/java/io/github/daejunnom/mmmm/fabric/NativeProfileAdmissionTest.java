package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.DoubleNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure boundary fixtures, never observed game artifacts or runtime-verification evidence.
 * Existing original examples cover reference metadata but not private authority/source admission.
 */
final class NativeProfileAdmissionTest {
    private static final String GAME_DIGEST = "a".repeat(64);
    private static final String HOST_DIGEST = "b".repeat(64);
    private static final String GENERATION = "31";
    private final ContractJson contracts = new ContractJson();

    private record Inputs(ObjectNode hello, ObjectNode facts, ObjectNode evidence) { }

    @Test void originalProfileAndHelloFixturesCanRepresentMatchingPrivateAdmissionWithoutChangingFacts() throws IOException {
        Inputs inputs = inputs(); contracts.validate("HostHello", inputs.hello()); contracts.validate("VersionProfile", inputs.evidence().path("profile"));
        String helloBefore = inputs.hello().toString(); String factsBefore = inputs.facts().toString(); String evidenceBefore = inputs.evidence().toString();
        assertDoesNotThrow(() -> require(inputs));
        assertEquals(helloBefore, inputs.hello().toString()); assertEquals(factsBefore, inputs.facts().toString()); assertEquals(evidenceBefore, inputs.evidence().toString());
        assertEquals("unknown", first(inputs.facts(), "serverPacks").path("packSourceCompleteness").asText());
        assertTrue(inputs.facts().path("clientPacks").isNull());
        assertEquals("not_observed", inputs.facts().path("transformedClassBytes").asText());
    }

    @Test void equalJsonIntegerPinsMatchAcrossConstructedHelloAndParsedAuthorityRepresentations() throws IOException {
        Inputs inputs = inputs(); ObjectNode constructedHello = inputs.hello().deepCopy().put("javaMajor", 25);
        ObjectNode parsedEvidence = ContractJson.object(ContractJson.parse(ContractJson.bytes(inputs.evidence())));
        assertTrue(constructedHello.path("javaMajor").isInt()); assertTrue(parsedEvidence.path("profile").path("javaMajor").isBigInteger());
        contracts.validate("HostHello", constructedHello); contracts.validate("VersionProfile", parsedEvidence.path("profile"));
        assertDoesNotThrow(() -> NativeProfileAdmission.require(contracts, parsedEvidence, constructedHello, inputs.facts(), HOST_DIGEST, GENERATION));
    }

    @Test void mathematicalInt32JavaMajorPinsAcceptDecimalAndExponentRepresentationsWithoutRewriting() throws IOException {
        for (String actual : Set.of("25", "25.0", "2.5e1")) {
            for (String approved : Set.of("25", "25.0", "2.5e1")) {
                Inputs inputs = inputs(); inputs.hello().set("javaMajor", jsonNumber(actual));
                inputs.evidence().withObject("profile").set("javaMajor", jsonNumber(approved));
                contracts.validate("HostHello", inputs.hello()); contracts.validate("VersionProfile", inputs.evidence().path("profile"));
                String helloBefore = inputs.hello().toString(), evidenceBefore = inputs.evidence().toString(), factsBefore = inputs.facts().toString();
                assertDoesNotThrow(() -> require(inputs));
                assertEquals(helloBefore, inputs.hello().toString()); assertEquals(evidenceBefore, inputs.evidence().toString()); assertEquals(factsBefore, inputs.facts().toString());
                assertEquals("unknown", first(inputs.facts(), "serverPacks").path("packSourceCompleteness").asText());
                assertEquals("not_observed", inputs.facts().path("transformedClassBytes").asText());
            }
        }
    }

    @Test void fractionalAndOutOfInt32JavaMajorPinsNeverTruncateOrOverflowToAnApprovedInteger() throws IOException {
        for (String invalid : Set.of("25.5", "2147483648", "2147483648.0", "-2147483649")) {
            Inputs actual = inputs(); actual.hello().set("javaMajor", jsonNumber(invalid));
            assertEquals("TARGET_PROFILE_UNVERIFIED", assertThrows(ContractException.class, () -> require(actual)).code());
            Inputs approved = inputs(); approved.evidence().withObject("profile").set("javaMajor", jsonNumber(invalid));
            assertThrows(ContractException.class, () -> require(approved));
        }
        for (String overflow : Set.of("2147483648", "2147483648.0")) {
            Inputs equalOverflow = inputs(); equalOverflow.hello().set("javaMajor", jsonNumber(overflow));
            equalOverflow.evidence().withObject("profile").set("javaMajor", jsonNumber(overflow));
            contracts.validate("HostHello", equalOverflow.hello()); contracts.validate("VersionProfile", equalOverflow.evidence().path("profile"));
            assertEquals("TARGET_PROFILE_UNVERIFIED", assertThrows(ContractException.class, () -> require(equalOverflow)).code());
        }
    }

    @Test void nonFiniteJavaMajorNodesAreRejectedInActualHelloAndAuthorityProfile() throws IOException {
        for (double invalid : new double[] {Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Double.NaN}) {
            Inputs actual = inputs(); actual.hello().set("javaMajor", DoubleNode.valueOf(invalid));
            assertEquals("TARGET_PROFILE_UNVERIFIED", assertThrows(ContractException.class, () -> require(actual)).code());
            Inputs approved = inputs(); approved.evidence().withObject("profile").set("javaMajor", DoubleNode.valueOf(invalid));
            assertThrows(ContractException.class, () -> require(approved));
        }
    }

    @Test void referenceBuildAndUnverifiedRuntimeMetadataCannotGrantWrites() throws IOException {
        for (String status : Set.of("reference_only", "build_verified")) {
            Inputs inputs = inputs(); ObjectNode profile = inputs.evidence().withObject("profile"); profile.put("validationStatus", status).put("writeSupport", "unverified");
            contracts.validate("VersionProfile", profile);
            assertEquals("TARGET_PROFILE_UNVERIFIED", assertThrows(ContractException.class, () -> require(inputs)).code());
        }
        for (String support : Set.of("unverified", "unsupported")) {
            Inputs inputs = inputs(); ObjectNode profile = inputs.evidence().withObject("profile"); profile.put("writeSupport", support);
            contracts.validate("VersionProfile", profile); assertThrows(ContractException.class, () -> require(inputs));
        }
    }

    @Test void originalGameArchiveAndHostImplementationHaveSeparatePins() throws IOException {
        Inputs inputs = inputs();
        assertNotEquals(inputs.evidence().path("profile").path("artifactSha256").asText(), inputs.evidence().path("hostArtifactDigest").asText());
        assertDoesNotThrow(() -> require(inputs));
        inputs.evidence().withObject("profile").put("artifactSha256", HOST_DIGEST);
        assertThrows(ContractException.class, () -> require(inputs), "A host archive receipt is not an original game input receipt");
        Inputs wrongHost = inputs(); wrongHost.evidence().put("hostArtifactDigest", GAME_DIGEST);
        assertThrows(ContractException.class, () -> require(wrongHost), "A game archive receipt is not the approved host implementation");
    }

    @Test void unavailableOrWrongScopeOriginalInputCannotBecomeAnObservedArtifactThroughMatchingHashes() throws IOException {
        Inputs unknown = inputs(); ObjectNode receipt = first(unknown.facts(), "originalInputGameJars");
        receipt.put("status", "unknown").put("reason", "ORIGINAL_GAME_INPUTS_UNAVAILABLE").putNull("sourceId"); refreshDigest(unknown);
        assertThrows(ContractException.class, () -> require(unknown));
        for (String scope : Set.of("container_input_bytes", "transformed_class_bytes", "runtime_class_code_source")) {
            Inputs wrongScope = inputs(); first(wrongScope.facts(), "originalInputGameJars").put("scope", scope); refreshDigest(wrongScope);
            assertThrows(ContractException.class, () -> require(wrongScope));
        }
        Inputs absent = inputs(); absent.facts().withArray("originalInputGameJars").removeAll(); refreshDigest(absent);
        assertThrows(ContractException.class, () -> require(absent));
    }

    @Test void onlyTopLevelObservationTimeIsVolatileUnderTheVersionedDigestRecipe() throws IOException {
        Inputs inputs = inputs(); ObjectNode sameFactsLater = inputs.facts().deepCopy().put("observedAt", "2026-10-14T00:00:00Z");
        assertEquals("mmmm.runtime-source-facts-digest/1", NativeProfileAdmission.DIGEST_RECIPE);
        assertEquals(NativeProfileAdmission.sourceDigest(inputs.facts()), NativeProfileAdmission.sourceDigest(sameFactsLater));
        assertDoesNotThrow(() -> NativeProfileAdmission.require(contracts, inputs.evidence(), inputs.hello(), sameFactsLater, HOST_DIGEST, GENERATION));
        assertEquals("2026-10-14T00:00:00Z", sameFactsLater.path("observedAt").asText());
        assertEquals("2026-10-13T12:00:00Z", inputs.facts().path("observedAt").asText(), "Digest projection must not mutate its input");
    }

    @Test void nestedObservationTimeAndUnknownReasonsStayInsideTheSourcePin() throws IOException {
        Inputs inputs = inputs();
        ObjectNode changedReason = inputs.facts().deepCopy(); changedReason.withObject("runtimeGame").withObject("serverClassCodeSource").put("reason", "SOURCE_CHANGED_DURING_OBSERVATION");
        assertChangedAndDenied(inputs, changedReason);
        ObjectNode nestedTimestamp = inputs.facts().deepCopy(); nestedTimestamp.withObject("runtimeGame").withObject("serverClassCodeSource").put("observedAt", "2026-10-13T12:00:00Z");
        assertChangedAndDenied(inputs, nestedTimestamp);
        ObjectNode laterNestedTimestamp = nestedTimestamp.deepCopy(); laterNestedTimestamp.withObject("runtimeGame").withObject("serverClassCodeSource").put("observedAt", "2026-10-13T12:00:01Z");
        assertNotEquals(NativeProfileAdmission.sourceDigest(nestedTimestamp), NativeProfileAdmission.sourceDigest(laterNestedTimestamp), "Only the top-level observation timestamp is omitted");
        ObjectNode unknownToClaimedKnown = inputs.facts().deepCopy(); first(unknownToClaimedKnown, "serverPacks").put("packSourceCompleteness", "complete");
        assertChangedAndDenied(inputs, unknownToClaimedKnown);
    }

    @Test void observedPackAndArchiveOrderCannotBeNormalizedAway() throws IOException {
        Inputs inputs = inputs(); ObjectNode reorderedPacks = inputs.facts().deepCopy(); reverseTwo(reorderedPacks.withArray("serverPacks"));
        assertChangedAndDenied(inputs, reorderedPacks);
        ObjectNode reorderedArchives = inputs.facts().deepCopy(); reverseTwo(reorderedArchives.withArray("archives"));
        assertChangedAndDenied(inputs, reorderedArchives);
    }

    @Test void archiveSizeIdentityAndRuntimeSourceMetadataRemainPinned() throws IOException {
        Inputs inputs = inputs(); ObjectNode changedSize = inputs.facts().deepCopy(); first(changedSize, "archives").put("sizeBytes", 4097);
        assertChangedAndDenied(inputs, changedSize);
        ObjectNode changedIdentity = inputs.facts().deepCopy(); first(changedIdentity, "archives").put("fileIdentityObservation", "unavailable");
        assertChangedAndDenied(inputs, changedIdentity);
        ObjectNode changedJava = inputs.facts().deepCopy(); changedJava.withObject("javaRuntime").put("version", "25.0.5+1");
        assertChangedAndDenied(inputs, changedJava);
        ObjectNode changedSourceEpoch = inputs.facts().deepCopy(); changedSourceEpoch.withObject("environment").put("sessionEpoch", "next-source-epoch");
        assertChangedAndDenied(inputs, changedSourceEpoch);
    }

    @Test void actualHelloGameJavaLoaderAndEnvironmentMustMatchTheReceipt() throws IOException {
        Inputs inputs = inputs(); ObjectNode newGame = inputs.hello().deepCopy().put("gameVersion", "26.4");
        assertThrows(ContractException.class, () -> NativeProfileAdmission.require(contracts, inputs.evidence(), newGame, inputs.facts(), HOST_DIGEST, GENERATION));
        ObjectNode newJava = inputs.hello().deepCopy().put("javaMajor", 21);
        assertThrows(ContractException.class, () -> NativeProfileAdmission.require(contracts, inputs.evidence(), newJava, inputs.facts(), HOST_DIGEST, GENERATION));
        ObjectNode newLoader = inputs.hello().deepCopy(); newLoader.withObject("loader").put("id", "fabric").put("version", "0.19.5");
        contracts.validate("HostHello", newLoader);
        assertThrows(ContractException.class, () -> NativeProfileAdmission.require(contracts, inputs.evidence(), newLoader, inputs.facts(), HOST_DIGEST, GENERATION));
        for (String identity : Set.of("sessionEpoch", "worldId", "gameInstanceId")) {
            ObjectNode newEnvironment = inputs.hello().deepCopy(); newEnvironment.withObject("environment").put(identity, "different-identity");
            assertThrows(ContractException.class, () -> NativeProfileAdmission.require(contracts, inputs.evidence(), newEnvironment, inputs.facts(), HOST_DIGEST, GENERATION));
        }
    }

    @Test void generationMustMatchAuthorityReceiptCurrentHostAndObservedFactsIndependently() throws IOException {
        Inputs inputs = inputs();
        assertThrows(ContractException.class, () -> NativeProfileAdmission.require(contracts, inputs.evidence(), inputs.hello(), inputs.facts(), HOST_DIGEST, "32"));
        Inputs changedFacts = inputs(); changedFacts.facts().put("registryGeneration", "32"); refreshDigest(changedFacts);
        assertThrows(ContractException.class, () -> require(changedFacts), "Refreshing a digest does not repair an actual generation mismatch");
        Inputs changedAuthority = inputs(); changedAuthority.evidence().put("registryGeneration", "32");
        assertThrows(ContractException.class, () -> require(changedAuthority));
    }

    @Test void evidenceSourceDigestAndClosedAuthorityCannotBeReplacedByCallerClaims() throws IOException {
        Inputs wrongDigest = inputs(); wrongDigest.evidence().put("runtimeSourceFactsDigest", "c".repeat(64));
        assertThrows(ContractException.class, () -> require(wrongDigest));
        Inputs extraGrant = inputs(); extraGrant.evidence().put("writeProfileVerified", true);
        assertThrows(ContractException.class, () -> require(extraGrant));
        Inputs missingPin = inputs(); missingPin.evidence().remove("runtimeSourceFactsDigest");
        assertThrows(ContractException.class, () -> require(missingPin));
        Inputs extraOriginalProfileField = inputs(); extraOriginalProfileField.evidence().withObject("profile").put("runtimeApproved", true);
        assertThrows(ContractException.class, () -> require(extraOriginalProfileField));
    }

    private static JsonNode jsonNumber(String value) { return ContractJson.parse(value.getBytes(StandardCharsets.UTF_8)); }
    private void require(Inputs inputs) { NativeProfileAdmission.require(contracts, inputs.evidence(), inputs.hello(), inputs.facts(), HOST_DIGEST, GENERATION); }
    private void assertChangedAndDenied(Inputs inputs, ObjectNode changedFacts) {
        assertNotEquals(NativeProfileAdmission.sourceDigest(inputs.facts()), NativeProfileAdmission.sourceDigest(changedFacts));
        assertThrows(ContractException.class, () -> NativeProfileAdmission.require(contracts, inputs.evidence(), inputs.hello(), changedFacts, HOST_DIGEST, GENERATION));
    }
    private static void refreshDigest(Inputs inputs) { inputs.evidence().put("runtimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(inputs.facts())); }
    private Inputs inputs() throws IOException {
        ObjectNode hello = fixture("host-hello.json"); ObjectNode profile = fixture("version-profile.json");
        profile.put("javaMajor", hello.path("javaMajor").intValue()).put("validationStatus", "runtime_verified").put("writeSupport", "verified").put("artifactSha256", GAME_DIGEST);
        profile.withArray("testedLoaders").removeAll().add(hello.path("loader").path("id").asText());
        profile.withArray("evidenceResourceIds").removeAll().add("evidence-fixture-original-game");
        ObjectNode facts = facts(hello); ObjectNode evidence = ContractJson.newObject().put("hostArtifactDigest", HOST_DIGEST).put("registryGeneration", GENERATION);
        evidence.set("profile", profile); evidence.put("runtimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(facts));
        return new Inputs(hello, facts, evidence);
    }
    private static ObjectNode facts(ObjectNode hello) {
        ObjectNode facts = ContractJson.newObject().put("format", "mmmm.native.source-facts/1").put("registryGeneration", GENERATION)
                .put("observedAt", "2026-10-13T12:00:00Z").put("archiveReceiptScope", "container_input_bytes")
                .put("transformedClassBytes", "not_observed").put("resourceContentEnumeration", "not_performed").put("developmentEnvironment", false);
        facts.set("environment", hello.path("environment").deepCopy());
        facts.putObject("javaRuntime").put("feature", hello.path("javaMajor").intValue()).put("version", "25.0.4+1").put("vendor", "fixture-only");
        ObjectNode gameArchive = archive(GAME_DIGEST, 4096); ObjectNode hostArchive = archive(HOST_DIGEST, 8192);
        ObjectNode minecraft = ContractJson.newObject().put("modId", "minecraft").put("modIdDigest", "d".repeat(64)).put("version", hello.path("gameVersion").asText());
        minecraft.putArray("runtimeRoots").add(gameArchive.deepCopy().put("rootIndex", 0)); minecraft.put("runtimeRootObservation", "observed_root_list");
        minecraft.putObject("installation").put("scope", "installation_origin").put("kind", "unknown").put("status", "unknown").put("reason", "INSTALLATION_ORIGIN_UNAVAILABLE");
        ObjectNode host = ContractJson.newObject().put("modId", "mmmm_host").put("modIdDigest", "c".repeat(64)).put("version", "0.1.0").put("runtimeRootObservation", "observed_root_list");
        host.putArray("runtimeRoots").add(hostArchive.deepCopy().put("rootIndex", 0));
        host.putObject("installation").put("status", "unknown").put("reason", "INSTALLATION_ORIGIN_UNAVAILABLE").putNull("sourceId");
        facts.putArray("mods").add(minecraft).add(host);
        ObjectNode runtimeGame = facts.putObject("runtimeGame"); runtimeGame.putArray("modRoots").add(gameArchive.deepCopy());
        runtimeGame.putObject("serverClassCodeSource").put("status", "unknown").put("reason", "SOURCE_ROOT_NOT_ORDINARY_ARCHIVE").putNull("sourceId");
        facts.putArray("originalInputGameJars").add(gameArchive.deepCopy().put("inputIndex", 0).put("scope", "original_game_input_container"));
        facts.putArray("serverPacks").add(pack("vanilla", 0)).add(pack("fixture-overlay", 1));
        facts.putNull("clientPacks").put("clientPackObservation", "not_observed"); facts.putArray("archives").add(gameArchive).add(hostArchive);
        facts.put("bytesRead", 12288).put("entryCount", 2); return facts;
    }
    private static ObjectNode archive(String digest, long size) {
        return ContractJson.newObject().put("status", "observed").put("sourceId", "archive-sha256-" + digest).put("sha256", digest)
                .put("sizeBytes", size).put("scope", "container_input_bytes").put("fileIdentityObservation", "stable_before_after");
    }
    private static ObjectNode pack(String id, int index) {
        ObjectNode pack = ContractJson.newObject().put("packIndex", index).put("packId", id).put("packIdDigest", "e".repeat(64))
                .put("resourceContentObservation", "not_enumerated").put("implementationClass", "fixture.NativePackResources")
                .putNull("providerModId").put("linkage", "unknown").put("packSourceCompleteness", "unknown").put("packSourceReason", "OPAQUE_PACK_RESOURCES");
        pack.putObject("location").put("id", id).put("idDigest", "f".repeat(64)).putNull("knownPackDescriptorDigest");
        pack.putArray("linkedRuntimeContainerSources"); return pack;
    }
    private static void reverseTwo(ArrayNode values) { JsonNode first = values.get(0).deepCopy(); values.set(0, values.get(1).deepCopy()); values.set(1, first); }
    private static ObjectNode first(ObjectNode value, String field) { return ContractJson.object(value.path(field).get(0)); }
    private static ObjectNode fixture(String name) throws IOException {
        Path source = Path.of(System.getProperty("mmmm.checkout"), "examples", name);
        try (var input = Files.newInputStream(source)) { return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1))); }
    }
}
