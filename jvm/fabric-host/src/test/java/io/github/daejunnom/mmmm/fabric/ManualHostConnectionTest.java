package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Existing public profiles do not exercise the new private owner-payload-to-typed-map boundary.
 * These negative transport fixtures prove no authority grant, JVM invocation or real game state.
 */
final class ManualHostConnectionTest {
    @Test void boundedOriginalProfileBytesRemainSeparateFromArtifactAndInterfacePins() throws IOException {
        byte[] raw = profileBytes(); ObjectNode entry = entry("owner.approval:1", HexFormat.of().formatHex(raw));
        entry.put("profileDigest", ContractJson.digest(ContractJson.parse(raw)));
        var decoded = ManualHostConnection.decodeCompatibilityApprovals(available(entry));
        assertEquals(1, decoded.size()); var actual = decoded.getFirst();
        assertEquals("owner.approval:1", actual.approvedProfileRef()); assertArrayEquals(raw, actual.rawProfile());
        assertEquals(entry.path("profileDigest").asText(), actual.profileDigest());
        assertEquals("b".repeat(64), actual.artifactDigest()); assertEquals("c".repeat(64), actual.allowedInterfaceDigest());
        byte[] copy = actual.rawProfile(); copy[0] ^= 1; assertArrayEquals(raw, actual.rawProfile());
        entry.put("profileBytesHex", "00"); assertArrayEquals(raw, actual.rawProfile());
        assertThrows(UnsupportedOperationException.class, () -> decoded.add(actual));
    }

    @Test void explicitUnavailableIsEmptyAndCannotConcealProfilesOrClaimAvailableReason() {
        assertTrue(ManualHostConnection.decodeCompatibilityApprovals(available()).isEmpty());
        ObjectNode unavailable = ContractJson.newObject().put("status", "unavailable").put("reasonCode", "APPROVAL_SOURCE_UNAVAILABLE");
        unavailable.putArray("profiles"); assertTrue(ManualHostConnection.decodeCompatibilityApprovals(unavailable).isEmpty());
        for (String status : List.of("unknown", "AVAILABLE", "disabled", "")) reject(unavailable.deepCopy().put("status", status));
        reject(unavailable.deepCopy().putNull("reasonCode"));
        reject(unavailable.deepCopy().put("reasonCode", "INTERFACE_CHECKED"));
        ObjectNode concealed = unavailable.deepCopy(); concealed.withArray("profiles").add(entry("hidden", "00")); reject(concealed);
        reject(available().put("reasonCode", "APPROVAL_SOURCE_UNAVAILABLE"));
        reject(available().put("ready", true));
        ObjectNode missing = available(); missing.remove("reasonCode"); reject(missing);
    }

    @Test void malformedAndDuplicateReferencesNeverProduceAPartialApprovalList() {
        for (String reference : List.of("", " ", "with space", "with/slash", "한글", "x".repeat(257))) {
            reject(available(entry("valid", "00"), entry(reference, "00")));
        }
        assertEquals(1, ManualHostConnection.decodeCompatibilityApprovals(available(entry("A".repeat(256), "00"))).size());
        reject(available(entry("same", "00"), entry("same", "00")));
        ObjectNode unknown = entry("valid", "00").put("approved", true); reject(available(unknown));
        ObjectNode missing = entry("valid", "00"); missing.remove("allowedInterfaceDigest"); reject(available(missing));
        ObjectNode wrongType = entry("valid", "00").put("artifactDigest", 1); reject(available(wrongType));
    }

    @Test void hexAndDigestCodecsRejectTruncationUppercaseAndOversizeWithoutAnApproval() {
        for (String hex : List.of("", "0", "000", "GG", "AA", "0g", "00 ", "00".repeat(65537))) {
            reject(available(entry("valid", "00"), entry("invalid", hex)));
        }
        for (String field : List.of("profileDigest", "artifactDigest", "allowedInterfaceDigest")) {
            for (String invalid : List.of("", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64))) {
                reject(available(entry("valid", "00").put(field, invalid)));
            }
        }
    }

    @Test void countAndDecodedByteBoundsAreIndependentAndExact() {
        ObjectNode count = available();
        for (int index = 0; index < 128; index++) count.withArray("profiles").add(entry("approval-" + index, "00"));
        assertEquals(128, ManualHostConnection.decodeCompatibilityApprovals(count).size());
        count.withArray("profiles").add(entry("approval-extra", "00")); reject(count);
        ObjectNode bytes = available(); String maximum = "00".repeat(65536);
        for (int index = 0; index < 4; index++) bytes.withArray("profiles").add(entry("approval-" + index, maximum));
        var decoded = ManualHostConnection.decodeCompatibilityApprovals(bytes);
        assertEquals(256 * 1024, decoded.stream().mapToInt(value -> value.rawProfile().length).sum());
        bytes.withArray("profiles").add(entry("approval-overflow", "00")); reject(bytes);
    }

    @Test void retainedTransportApprovalReportsUnavailableWithoutCallingAnApprovalIssuer() {
        var typed = ManualHostConnection.decodeCompatibilityApprovals(available(entry("retained", "00")));
        try (NativeCompatibilityApprovals approvals = new NativeCompatibilityApprovals(new ContractJson(), typed,
                (profile, environment, generation) -> fail("Unavailable inspection must not issue a current approval"))) {
            ObjectNode request = ContractJson.newObject().put("kind", "compatibility_interface")
                    .put("approvedProfileRef", "retained").put("profileDigest", "a".repeat(64));
            assertEquals("COMPATIBILITY_SOURCE_UNAVAILABLE", assertThrows(ContractException.class, () -> approvals.inspectUnavailable(request)).code());
            assertEquals("PROFILE_UNAPPROVED", assertThrows(ContractException.class,
                    () -> approvals.inspectUnavailable(request.deepCopy().put("approvedProfileRef", "unretained"))).code());
            assertEquals("PROFILE_UNAPPROVED", assertThrows(ContractException.class,
                    () -> approvals.inspectUnavailable(request.deepCopy().put("profileDigest", "d".repeat(64)))).code());
            assertEquals("PROFILE_UNAPPROVED", assertThrows(ContractException.class,
                    () -> approvals.inspectUnavailable(request.deepCopy().put("approved", true))).code());
        }
    }

    private static byte[] profileBytes() throws IOException {
        return Files.readAllBytes(Path.of(System.getProperty("mmmm.checkout")).resolve("examples/compat-public-java.json"));
    }
    private static ObjectNode entry(String reference, String bytes) {
        return ContractJson.newObject().put("approvedProfileRef", reference).put("profileBytesHex", bytes)
                .put("profileDigest", "a".repeat(64)).put("artifactDigest", "b".repeat(64)).put("allowedInterfaceDigest", "c".repeat(64));
    }
    private static ObjectNode available(ObjectNode... profiles) {
        ObjectNode value = ContractJson.newObject().put("status", "available").putNull("reasonCode");
        var array = value.putArray("profiles"); for (ObjectNode profile : profiles) array.add(profile); return value;
    }
    private static void reject(JsonNode payload) {
        assertThrows(ContractException.class, () -> ManualHostConnection.decodeCompatibilityApprovals(payload));
    }
}
