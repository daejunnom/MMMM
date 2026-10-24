package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.host.GameThread;
import io.github.daejunnom.mmmm.host.HostAuthority;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.javaadapter.ApprovedArtifact;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.time.Clock;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Existing public profiles do not exercise the new private owner-payload-to-typed-map boundary.
 * These negative transport fixtures prove no authority grant, JVM invocation or real game state.
 */
final class ManualHostConnectionTest {
    @TempDir Path temporary;
    @Test void calibrationCompletionBindsTheExactPurposeSelectionManifestAndOriginalHostContext() {
        ObjectNode offer = ContractJson.newObject().put("nonce", "approve-fixture");
        offer.putObject("hostHello").putObject("environment").put("sessionEpoch", "epoch-fixture-01"); offer.putArray("contextIds").add("context-fixture-01");
        ObjectNode completed = ContractJson.newObject().put("kind", "host_apply_approval_complete").put("protocolVersion", ContractJson.VERSION)
                .put("nonce", "approve-fixture").put("ready", true).put("coordinatorEpoch", "coordinator-fixture")
                .put("hostEpoch", "epoch-fixture-01").put("contextId", "context-fixture-01").put("purpose", NativeCalibrationApproval.PURPOSE)
                .put("selectionDigest", "a".repeat(64)).put("manifestDigest", "b".repeat(64));
        assertDoesNotThrow(() -> ManualHostConnection.validateCalibrationCompletion(offer, completed, "a".repeat(64), "b".repeat(64)));
        for (String field : List.of("kind", "protocolVersion", "nonce", "coordinatorEpoch", "hostEpoch", "contextId", "purpose", "selectionDigest", "manifestDigest")) {
            ObjectNode changed = completed.deepCopy().put(field, "changed value");
            assertThrows(ContractException.class, () -> ManualHostConnection.validateCalibrationCompletion(offer, changed, "a".repeat(64), "b".repeat(64)));
        }
        assertThrows(ContractException.class, () -> ManualHostConnection.validateCalibrationCompletion(offer, completed.deepCopy().put("ready", false), "a".repeat(64), "b".repeat(64)));
        ObjectNode omitted = completed.deepCopy(); omitted.remove("manifestDigest");
        assertThrows(ContractException.class, () -> ManualHostConnection.validateCalibrationCompletion(offer, omitted, "a".repeat(64), "b".repeat(64)));
        assertThrows(ContractException.class, () -> ManualHostConnection.validateCalibrationCompletion(offer, completed.deepCopy().put("admin", true), "a".repeat(64), "b".repeat(64)));
        assertThrows(ContractException.class, () -> ManualHostConnection.validateCalibrationCompletion(offer, completed, null, "b".repeat(64)));
    }

    @Test void bootstrapCompletionCannotAdoptNumericApprovalOrCallerAuthorityFields() {
        ObjectNode offer = ContractJson.newObject().put("nonce", "bootstrap-fixture").put("purpose", NativeCalibrationBootstrap.PURPOSE);
        offer.putObject("hostHello").putObject("environment").put("sessionEpoch", "epoch-fixture-01");
        offer.putArray("contextIds").add("context-fixture-01");
        ObjectNode completed = ContractJson.newObject().put("kind", "host_apply_approval_complete").put("protocolVersion", ContractJson.VERSION)
                .put("nonce", "bootstrap-fixture").put("ready", true).put("coordinatorEpoch", "coordinator-fixture")
                .put("hostEpoch", "epoch-fixture-01").put("contextId", "context-fixture-01").put("purpose", NativeCalibrationBootstrap.PURPOSE)
                .put("selectionDigest", "a".repeat(64)).put("manifestDigest", "b".repeat(64));
        assertDoesNotThrow(() -> ManualHostConnection.validateBootstrapCompletion(offer, completed, "a".repeat(64), "b".repeat(64)));
        for (String field : List.of("kind", "protocolVersion", "nonce", "coordinatorEpoch", "hostEpoch", "contextId", "purpose", "selectionDigest", "manifestDigest")) {
            ObjectNode changed = completed.deepCopy().put(field, "changed value");
            assertThrows(ContractException.class, () -> ManualHostConnection.validateBootstrapCompletion(offer, changed, "a".repeat(64), "b".repeat(64)));
        }
        assertThrows(ContractException.class, () -> ManualHostConnection.validateBootstrapCompletion(offer,
                completed.deepCopy().put("purpose", NativeCalibrationApproval.PURPOSE), "a".repeat(64), "b".repeat(64)));
        assertThrows(ContractException.class, () -> ManualHostConnection.validateCalibrationCompletion(offer, completed, "a".repeat(64), "b".repeat(64)));
        assertThrows(ContractException.class, () -> ManualHostConnection.validateBootstrapCompletion(
                offer.deepCopy().put("purpose", NativeCalibrationApproval.PURPOSE), completed, "a".repeat(64), "b".repeat(64)));
        assertThrows(ContractException.class, () -> ManualHostConnection.validateBootstrapCompletion(offer,
                completed.deepCopy().put("verifiedWriteProfile", true), "a".repeat(64), "b".repeat(64)));
        assertThrows(ContractException.class, () -> ManualHostConnection.validateBootstrapCompletion(offer,
                completed.deepCopy().put("ready", false), "a".repeat(64), "b".repeat(64)));
    }

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

    /** Existing wire examples cannot exercise source I/O, per-request cache lifetime or source changes. */
    @Test void ordinaryMetadataSnapshotReusesTheExactJarAndNeverCarriesARequestBeyondItsScope() throws IOException {
        Path jar = metadataJar("ordinary.jar"); var first = metadataApproval("first", jar); var second = metadataApproval("second", jar);
        NativeCompatibilityMetadataResolver.ModIdentity identity = new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", jar);
        try (var resolver = metadataResolver(List.of(first, second), (id, checkpoint) -> { checkpoint.run(); return identity; })) {
            var selected = resolver.inScope(() -> { }, () -> {
                var one = resolver.resolve(first); var two = resolver.resolve(second);
                assertNotNull(one); assertNotNull(two); assertSame(one.artifact(), two.artifact());
                assertEquals(first.artifactDigest(), one.artifact().sha256());
                assertTrue(one.artifact().retainedSnapshotBytes() > 0);
                assertEquals("fabric", one.target().loader()); assertEquals("fixture_legacy", one.target().modId());
                assertEquals("0.1.0", one.target().modVersion()); assertEquals("26.3", one.target().gameVersion());
                return one;
            });
            assertEquals("COMPATIBILITY_SOURCE_UNAVAILABLE", assertThrows(ContractException.class,
                    selected.currentMetadataApproval()::checkpoint).code(), "No original request control survives the scope");
            resolver.inScope(() -> { }, () -> { assertSame(selected.artifact(), resolver.resolve(first).artifact()); return null; });
        }
    }

    @Test void unobservedOriginsDirectoriesAndSecretSelectorsCannotOpenAnArtifact() throws IOException {
        Path jar = metadataJar("ordinary.jar"); var approval = metadataApproval("source", jar);
        List<NativeCompatibilityMetadataResolver.ModIdentity> identities = new java.util.ArrayList<>();
        identities.add(null);
        identities.add(new NativeCompatibilityMetadataResolver.ModIdentity("other_mod", "0.1.0", jar));
        identities.add(new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", Files.createDirectory(temporary.resolve("directory.jar"))));
        // This selector is never created, stat'ed or opened; it only exercises the pre-access guard.
        identities.add(new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", temporary.resolve(".env.fixture.jar")));
        for (var identity : identities) {
            try (var resolver = metadataResolver(List.of(approval), (id, checkpoint) -> identity)) {
                assertNull(resolver.inScope(() -> { }, () -> resolver.resolve(approval)));
            }
        }
        assertTrue(NativeCompatibilityMetadataResolver.secretSelector("service-account.json"));
        assertTrue(NativeCompatibilityMetadataResolver.secretSelector("id_ed25519"));
        assertFalse(NativeCompatibilityMetadataResolver.secretSelector("public-mod.jar"));
    }

    @Test void metadataSourcePinAndActualVersionChangesRemainFatalInsteadOfUnsupported() throws IOException {
        Path jar = metadataJar("ordinary.jar"); var approval = metadataApproval("source", jar);
        var live = new AtomicReference<>(new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", jar));
        try (var resolver = metadataResolver(List.of(approval), (id, checkpoint) -> live.get())) {
            ContractException changed = assertThrows(ContractException.class, () -> resolver.inScope(() -> { }, () -> {
                resolver.resolve(approval); live.set(new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.2.0", jar)); return null;
            }));
            assertEquals("SOURCE_CHANGED", changed.code());
        }
        var wrongPin = new NativeCompatibilityApprovals.ApprovedProfile("wrong", approval.rawProfile(), approval.profileDigest(), "d".repeat(64), approval.allowedInterfaceDigest());
        live.set(new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", jar));
        try (var resolver = metadataResolver(List.of(approval, wrongPin), (id, checkpoint) -> live.get())) {
            ContractException changed = assertThrows(ContractException.class, () -> resolver.inScope(() -> { }, () -> {
                resolver.resolve(approval); return resolver.resolve(wrongPin);
            }));
            assertEquals("SOURCE_CHANGED", changed.code());
        }
    }

    @Test void metadataPostReadDetectsAnActualOwnedFixtureFileChange() throws IOException {
        Path jar = metadataJar("ordinary.jar"); var approval = metadataApproval("source", jar);
        var identity = new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", jar);
        try (var resolver = metadataResolver(List.of(approval), (id, checkpoint) -> identity)) {
            ContractException changed = assertThrows(ContractException.class, () -> resolver.inScope(() -> { }, () -> {
                resolver.resolve(approval);
                try { Files.write(jar, new byte[] { 0 }, java.nio.file.StandardOpenOption.APPEND); }
                catch (IOException exception) { throw new AssertionError(exception); }
                return null;
            }));
            assertEquals("SOURCE_CHANGED", changed.code());
        }
    }

    @Test void metadataGetterFailurePreservesOriginalCancellationAndClearsTheTransientScope() throws IOException {
        Path jar = metadataJar("ordinary.jar"); var approval = metadataApproval("source", jar);
        var identity = new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", jar);
        AtomicBoolean cancelled = new AtomicBoolean();
        ContractException primary = new ContractException("FIXTURE_READ_FAILED", "Owned fixture body failed");
        ContractException stopped = new ContractException("CANCELLATION_REQUESTED", "Original fixture request stopped");
        try (var resolver = metadataResolver(List.of(approval), (id, checkpoint) -> identity)) {
            ContractException actual = assertThrows(ContractException.class, () -> resolver.inScope(() -> { if (cancelled.get()) throw stopped; }, () -> {
                resolver.resolve(approval); cancelled.set(true); throw primary;
            }));
            assertSame(primary, actual); assertArrayEquals(new Throwable[] { stopped }, actual.getSuppressed());
            cancelled.set(false);
            resolver.inScope(() -> { }, () -> { assertNotNull(resolver.resolve(approval)); return null; });
            AssertionError fatal = new AssertionError("Owned fixture fatal body");
            assertSame(fatal, assertThrows(AssertionError.class, () -> resolver.inScope(() -> { }, () -> { throw fatal; })));
            resolver.inScope(() -> { }, () -> { assertNotNull(resolver.resolve(approval)); return null; });
        }
    }

    @Test void structuralArtifactFailureRetainsItsTypedCauseWithoutBecomingAMetadataFact() throws IOException {
        Path jar = temporary.resolve("invalid.jar"); Files.writeString(jar, "invalid source input");
        var approval = metadataApproval("invalid", jar);
        var identity = new NativeCompatibilityMetadataResolver.ModIdentity("fixture_legacy", "0.1.0", jar);
        try (var resolver = metadataResolver(List.of(approval), (id, checkpoint) -> identity)) {
            ContractException unavailable = assertThrows(ContractException.class,
                    () -> resolver.inScope(() -> { }, () -> resolver.resolve(approval)));
            assertEquals("METADATA_UNAVAILABLE", unavailable.code());
            assertEquals("SOURCE_INVALID", ((ContractException) unavailable.getSuppressed()[0]).code());
        }
    }

    @Test void optionalMetadataFailuresRetainBothReasonsAndLeaveTheNativeBaselineAlone() throws IOException {
        Path jar = temporary.resolve("invalid.jar"); Files.writeString(jar, "invalid source input");
        var first = metadataApproval("first", jar); var second = metadataApproval("second", jar, "fixture_other");
        List<NativeCompatibilityApprovals.ApprovedProfile> profiles = List.of(first, second);
        try (var resolver = metadataResolver(profiles, (id, checkpoint) -> "fixture_legacy".equals(id)
                ? new NativeCompatibilityMetadataResolver.ModIdentity(id, "0.1.0", jar) : null);
             var holder = new NativeCompatibilityApprovals(new ContractJson(), profiles, resolver::checkApproval);
             var runtime = metadataRuntime(holder)) {
            ObjectNode baseline = runtime.inventory(); ObjectNode environment = example("execution-context.json").withObject("environment").deepCopy();
            resolver.inScope(() -> { }, () -> { holder.registerMetadataBeforeFreeze(runtime, environment, "31", resolver); return null; });
            assertEquals(baseline, runtime.inventory());
            assertEquals("METADATA_UNAVAILABLE", holder.metadataUnavailableReason("first"));
            assertEquals(List.of("SOURCE_INVALID"), holder.metadataUnavailableCauseCodes("first"));
            assertEquals("METADATA_SOURCE_UNSUPPORTED", holder.metadataUnavailableReason("second"));
            ObjectNode request = ContractJson.newObject().put("kind", "compatibility_interface")
                    .put("approvedProfileRef", first.approvedProfileRef()).put("profileDigest", first.profileDigest());
            ContractException unavailable = assertThrows(ContractException.class,
                    () -> resolver.inScope(() -> { }, () -> holder.inspect(runtime, environment, "31", request)));
            assertEquals("COMPATIBILITY_SOURCE_UNAVAILABLE", unavailable.code());
        }
    }

    @Test void cancellationInALaterProfileCannotCommitEarlierMetadataOrBecomeOptionalUnavailable() throws IOException {
        Path jar = temporary.resolve("invalid.jar"); Files.writeString(jar, "invalid source input");
        var first = metadataApproval("first", jar); var second = metadataApproval("second", jar, "fixture_other");
        List<NativeCompatibilityApprovals.ApprovedProfile> profiles = List.of(first, second);
        AtomicBoolean cancelled = new AtomicBoolean(); ContractException stopped = new ContractException("CANCELLATION_REQUESTED", "Original fixture request stopped");
        try (var resolver = metadataResolver(profiles, (id, checkpoint) -> {
            if ("fixture_other".equals(id)) { cancelled.set(true); throw stopped; }
            return new NativeCompatibilityMetadataResolver.ModIdentity(id, "0.1.0", jar);
        }); var holder = new NativeCompatibilityApprovals(new ContractJson(), profiles, resolver::checkApproval);
             var runtime = metadataRuntime(holder)) {
            ObjectNode baseline = runtime.inventory(); ObjectNode environment = example("execution-context.json").withObject("environment").deepCopy();
            ContractException actual = assertThrows(ContractException.class, () -> resolver.inScope(() -> { if (cancelled.get()) throw stopped; }, () -> {
                holder.registerMetadataBeforeFreeze(runtime, environment, "31", resolver); return null;
            }));
            assertSame(stopped, actual); assertEquals(baseline, runtime.inventory());
        }
    }

    @Test void precommitMetadataCapacityFailureKeepsOnlyTheNativeBaselineAndAllTypedReasons() throws IOException {
        Path jar = metadataJar("ordinary.jar"); List<NativeCompatibilityApprovals.ApprovedProfile> profiles = new java.util.ArrayList<>();
        for (int index = 0; index < 128; index++) profiles.add(scalarMetadataApproval("profile-" + index, jar, index));
        String digest = ContractJson.sha256(Files.readAllBytes(jar));
        ClassLoader fixtureLoader = ApprovedArtifact.openMetadata(temporary, jar, actual -> assertEquals(digest, actual), () -> { }, Files.size(jar)).fixtureLoader();
        try (var resolver = metadataResolver(profiles, (id, checkpoint) -> new NativeCompatibilityMetadataResolver.ModIdentity(id, "0.1.0", jar), fixtureLoader);
             var holder = new NativeCompatibilityApprovals(new ContractJson(), profiles, resolver::checkApproval);
             var runtime = metadataRuntime(holder)) {
            ObjectNode baseline = runtime.inventory(); ObjectNode environment = example("execution-context.json").withObject("environment").deepCopy();
            resolver.inScope(() -> { }, () -> { holder.registerMetadataBeforeFreeze(runtime, environment, "31", resolver); return null; });
            assertEquals(baseline, runtime.inventory(), "No metadata Registrar mutation occurs before capacity admission");
            for (var profile : profiles) {
                assertEquals("METADATA_UNAVAILABLE", holder.metadataUnavailableReason(profile.approvedProfileRef()));
                assertEquals(List.of("REGISTRATION_LIMIT"), holder.metadataUnavailableCauseCodes(profile.approvedProfileRef()));
            }
        }
    }

    @Test void anEarlierCurrentnessCauseCannotBeDowngradedAfterALaterSuccessfulCheckpoint() throws IOException {
        Path jar = metadataJar("ordinary.jar"); var profile = metadataApproval("profile", jar);
        ContractException unavailable = new ContractException("METADATA_UNAVAILABLE", "Fixture metadata read failed");
        ContractException drift = new ContractException("SOURCE_CHANGED", "Fixture postcheck observed source drift"); unavailable.addSuppressed(drift);
        try (var resolver = metadataResolver(List.of(profile), (id, checkpoint) -> { throw unavailable; });
             var holder = new NativeCompatibilityApprovals(new ContractJson(), List.of(profile), resolver::checkApproval);
             var runtime = metadataRuntime(holder)) {
            ObjectNode baseline = runtime.inventory(); ObjectNode environment = example("execution-context.json").withObject("environment").deepCopy();
            ContractException actual = assertThrows(ContractException.class, () -> resolver.inScope(() -> { }, () -> {
                holder.registerMetadataBeforeFreeze(runtime, environment, "31", resolver); return null;
            }));
            assertSame(unavailable, actual); assertSame(drift, actual.getSuppressed()[0]); assertEquals(baseline, runtime.inventory());
        }
    }

    @Test void commitFailureIsFatalAndItsPartiallyAssembledCandidateMustBeDiscarded() throws IOException {
        Path jar = metadataJar("ordinary.jar"); var profile = scalarMetadataApproval("profile", jar, 0);
        String digest = ContractJson.sha256(Files.readAllBytes(jar));
        ClassLoader fixtureLoader = ApprovedArtifact.openMetadata(temporary, jar, actual -> assertEquals(digest, actual), () -> { }, Files.size(jar)).fixtureLoader();
        try (var resolver = metadataResolver(List.of(profile), (id, checkpoint) -> new NativeCompatibilityMetadataResolver.ModIdentity(id, "0.1.0", jar), fixtureLoader);
             var holder = new NativeCompatibilityApprovals(new ContractJson(), List.of(profile), resolver::checkApproval)) {
            HostRuntime candidate = metadataRuntime(holder, true);
            ObjectNode environment = example("execution-context.json").withObject("environment").deepCopy();
            try {
                ContractException failed = assertThrows(ContractException.class, () -> resolver.inScope(() -> { }, () -> {
                    holder.registerMetadataBeforeFreeze(candidate, environment, "31", resolver); return null;
                }));
                assertEquals("FIXTURE_REGISTRATION_FAILED", failed.code());
                // This is deliberately not a rollback claim. The production host closes the whole
                // candidate on this fatal path instead of keeping its partial provider inventory.
                assertEquals(2, candidate.inventory().path("providers").size());
            } finally { candidate.close(); }
            assertTrue(candidate.inventory().path("providers").isEmpty());
        }
    }

    private NativeCompatibilityMetadataResolver metadataResolver(List<NativeCompatibilityApprovals.ApprovedProfile> approvals,
            NativeCompatibilityMetadataResolver.ModLookup mods) throws IOException {
        return metadataResolver(approvals, mods, getClass().getClassLoader());
    }
    private NativeCompatibilityMetadataResolver metadataResolver(List<NativeCompatibilityApprovals.ApprovedProfile> approvals,
            NativeCompatibilityMetadataResolver.ModLookup mods, ClassLoader loader) throws IOException {
        ObjectNode environment = ContractJson.object(ContractJson.parse(Files.readAllBytes(Path.of(System.getProperty("mmmm.checkout"), "examples/execution-context.json"))))
                .withObject("environment").deepCopy();
        // These are fixture orchestration ports. They do not authorize a game receiver or execution.
        return new NativeCompatibilityMetadataResolver(new ContractJson(), approvals, environment, "31", "26.3", loader,
                () -> { }, () -> { }, mods);
    }
    private NativeCompatibilityApprovals.ApprovedProfile metadataApproval(String reference, Path jar) throws IOException {
        return metadataApproval(reference, jar, "fixture_legacy");
    }
    private NativeCompatibilityApprovals.ApprovedProfile metadataApproval(String reference, Path jar, String modId) throws IOException {
        ObjectNode profile = ContractJson.object(ContractJson.parse(profileBytes()));
        profile.withObject("match").put("modId", modId);
        String digest = ContractJson.sha256(Files.readAllBytes(jar)); profile.withObject("action").put("implementationDigest", digest);
        return new NativeCompatibilityApprovals.ApprovedProfile(reference, ContractJson.bytes(profile), ContractJson.digest(profile), digest, "c".repeat(64));
    }
    private Path metadataJar(String name) throws IOException {
        Path jar = temporary.resolve(name);
        String resource = MetadataFixture.class.getName().replace('.', '/') + ".class";
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new ZipEntry(resource));
            try (var source = getClass().getResourceAsStream("/" + resource)) { assertNotNull(source); output.write(source.readAllBytes()); }
            output.closeEntry();
        }
        return jar;
    }
    public static final class MetadataFixture { public static int value() { return 7; } }

    private NativeCompatibilityApprovals.ApprovedProfile scalarMetadataApproval(String reference, Path jar, int ordinal) throws IOException {
        ObjectNode profile = ContractJson.object(ContractJson.parse(profileBytes())); String digest = ContractJson.sha256(Files.readAllBytes(jar));
        profile.put("profileId", "fixture:metadata_" + ordinal); ObjectNode action = profile.withObject("action");
        action.put("actionId", "fixture:metadata_" + ordinal).put("implementationDigest", digest).put("planning", "unsupported")
                .put("semanticKind", "mmmm:diagnostic.value"); action.putArray("guarantees");
        ObjectNode input = ContractJson.newObject().put("type", "object").put("additionalProperties", false); input.putObject("properties");
        action.set("inputSchema", input); action.set("outputSchema", ContractJson.newObject().put("type", "integer"));
        ObjectNode binding = profile.withObject("binding").put("ownerClass", MetadataFixture.class.getName()).put("methodName", "value")
                .put("returnType", "int").put("resultCodec", "scalar"); binding.putArray("parameterTypes"); binding.putArray("arguments");
        ObjectNode support = ContractJson.newObject().put("kind", "public_java").put("publicLookupChecked", true)
                .put("initializationPerformed", false).put("threadAffinity", "server_main");
        ObjectNode signature = support.putObject("signature");
        for (String key : List.of("ownerClass", "methodName", "parameterTypes", "returnType", "receiver")) signature.set(key, binding.get(key).deepCopy());
        support.putNull("receiverResolver"); support.putArray("scopedHandleTypes");
        ObjectNode projection = ContractJson.newObject().put("kind", "mmmm-interface-observation/1").put("side", "server")
                .put("loader", "fabric").put("targetGameVersion", "26.3").put("modId", "fixture_legacy").put("modVersion", "0.1.0")
                .put("hostProtocolVersion", ContractJson.VERSION).put("implementationDigest", digest); projection.set("support", support);
        return new NativeCompatibilityApprovals.ApprovedProfile(reference, ContractJson.bytes(profile), ContractJson.digest(profile), digest, ContractJson.digest(projection));
    }

    private HostRuntime metadataRuntime(NativeCompatibilityApprovals holder) throws IOException {
        return metadataRuntime(holder, false);
    }
    private HostRuntime metadataRuntime(NativeCompatibilityApprovals holder, boolean rejectMetadataAction) throws IOException {
        ObjectNode hello = example("host-hello.json");
        HostAuthority deniedExecution = new HostAuthority() {
            @Override public boolean ready() { return false; }
            @Override public ObjectNode hello() { return hello.deepCopy(); }
            @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) { throw new ContractException("FIXTURE_EXECUTION_DENIED", "Registry fixture has no execution authority"); }
            @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) { throw new ContractException("FIXTURE_EXECUTION_DENIED", "Registry fixture has no execution authority"); }
        };
        HostRuntime runtime = new HostRuntime(new ContractJson(), new GameThread() {
            @Override public boolean isSameThread() { return true; }
            @Override public void execute(Runnable action) { action.run(); }
        }, deniedExecution, (binding, descriptor) -> {
            if (binding.startsWith("compat-")) {
                holder.checkRegistration(binding, descriptor);
                if (rejectMetadataAction && !descriptor.has("providerId")) throw new ContractException("FIXTURE_REGISTRATION_FAILED", "Owned fixture Registrar rejected the metadata action");
            }
        }, Clock.systemUTC());
        ObjectNode baseline = example("provider-supported.json"); baseline.putArray("actions"); runtime.registerProvider(baseline); return runtime;
    }
    private static ObjectNode example(String name) throws IOException {
        return ContractJson.object(ContractJson.parse(Files.readAllBytes(Path.of(System.getProperty("mmmm.checkout"), "examples", name))));
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
