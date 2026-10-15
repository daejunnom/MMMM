package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.javaadapter.ApprovedArtifact;
import io.github.daejunnom.mmmm.javaadapter.CompatibilityInterfaceProbe;
import io.github.daejunnom.mmmm.javaadapter.PublicJavaAdapter;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Transient, bounded approved compatibility registrations. Rust owns the durable approval records. */
final class NativeCompatibilityApprovals implements AutoCloseable {
    private static final int MAX_PROFILES = 128;
    private static final int MAX_PROFILE_BYTES = 256 * 1024;

    /**
     * A transport value, never an authority grant by itself. The native owner issuer first checks its
     * protected record, exact ResourceRef raw bytes, current policy, local-use scope and source rights.
     */
    record ApprovedProfile(String approvedProfileRef, byte[] rawProfile, String profileDigest,
                           String artifactDigest, String allowedInterfaceDigest) {
        ApprovedProfile {
            if (approvedProfileRef == null || !approvedProfileRef.matches("[A-Za-z0-9_.:-]{1,256}")
                    || rawProfile == null || rawProfile.length == 0 || rawProfile.length > CompatibilityInterfaceProbe.MAX_PROFILE_BYTES
                    || !digest(profileDigest) || !digest(artifactDigest) || !digest(allowedInterfaceDigest)) {
                throw failure("PROFILE_UNAPPROVED", "Compatibility approval requires bounded raw bytes and distinct exact pins");
            }
            rawProfile = rawProfile.clone();
        }
        @Override public byte[] rawProfile() { return rawProfile.clone(); }
    }

    @FunctionalInterface interface CurrentApproval {
        /** Rechecks the actual owner-issued approval, current policy and the actual host generation. */
        void check(ApprovedProfile profile, ObjectNode actualEnvironment, String actualRegistryGeneration);
    }
    @FunctionalInterface interface TargetResolver {
        /** Resolves only an approved actual loaded mod; metadata or the profile is not class-definition proof. */
        ResolvedTarget resolve(ApprovedProfile profile);
    }
    record ResolvedTarget(ApprovedArtifact artifact, ClassLoader loader,
                          ApprovedArtifact.LoadedClassApproval classApproval,
                          PublicJavaAdapter.RuntimeTarget target, PublicJavaAdapter.ProfileApproval currentSourceApproval) {
        ResolvedTarget {
            if (artifact == null || loader == null || classApproval == null || target == null || currentSourceApproval == null) {
                throw failure("SOURCE_UNAPPROVED", "Actual loaded artifact, definition collector and current source approval are required");
            }
        }
    }
    interface MetadataTargetResolver {
        /** Null means this actual source cannot provide metadata; it grants no fallback execution path. */
        ResolvedMetadataTarget resolve(ApprovedProfile profile);
        /** Final source pin/control check after all detection and before the actual Registrar commit. */
        void checkCurrentSources();
    }
    record ResolvedMetadataTarget(ApprovedArtifact artifact, ClassLoader loader, PublicJavaAdapter.RuntimeTarget target,
                                  CompatibilityInterfaceProbe.MetadataApproval currentMetadataApproval) {
        ResolvedMetadataTarget {
            if (artifact == null || loader == null || target == null || currentMetadataApproval == null) {
                throw failure("METADATA_UNAVAILABLE", "Actual source inputs and current metadata scope are required");
            }
        }
    }

    private final ContractJson contracts;
    private final List<ApprovedProfile> approvals;
    private final CurrentApproval currentApproval;
    private final Map<String, CompatibilityInterfaceProbe> registered = new LinkedHashMap<>();
    private final Map<String, CompatibilityInterfaceProbe> registering = new LinkedHashMap<>();
    private final Map<String, CompatibilityInterfaceProbe.MetadataProbe> metadataRegistered = new LinkedHashMap<>();
    private final Map<String, CompatibilityInterfaceProbe.MetadataProbe> metadataRegistering = new LinkedHashMap<>();
    private final Map<String, String> metadataUnavailableReasons = new LinkedHashMap<>();
    private final Map<String, List<String>> metadataUnavailableCauses = new LinkedHashMap<>();
    private HostRuntime runtime;
    private ObjectNode environment;
    private String registryGeneration;
    private boolean closed;

    NativeCompatibilityApprovals(ContractJson contracts, List<ApprovedProfile> approvals, CurrentApproval currentApproval) {
        if (contracts == null || approvals == null || currentApproval == null || approvals.size() > MAX_PROFILES
                || approvals.stream().anyMatch(value -> value == null)) {
            throw failure("PROFILE_UNAPPROVED", "Trusted current approval and a bounded approval set are required");
        }
        this.contracts = contracts; this.approvals = List.copyOf(approvals); this.currentApproval = currentApproval;
        int retainedBytes = 0; var references = new java.util.HashSet<String>();
        for (ApprovedProfile approval : this.approvals) {
            if (approval == null || !references.add(approval.approvedProfileRef())) {
                throw failure("PROFILE_UNAPPROVED", "Compatibility approval references must be distinct");
            }
            retainedBytes += approval.rawProfile.length;
            if (retainedBytes > MAX_PROFILE_BYTES) throw failure("INPUT_LIMIT", "Compatibility approval raw bytes exceed the host bound");
        }
    }

    /**
     * Trusted install composition only, before the actual Registrar generation is frozen. On failure
     * the caller closes its partially assembled HostRuntime; no public inspection can call this method.
     */
    void registerBeforeFreeze(HostRuntime actualRuntime, ObjectNode actualEnvironment,
                              String actualRegistryGeneration, TargetResolver resolver) {
        if (closed || runtime != null || actualRuntime == null || resolver == null
                || actualRegistryGeneration == null || !actualRegistryGeneration.matches("0|[1-9][0-9]*")) {
            throw failure("REGISTRATION_CLOSED", "Compatibility registration requires one current open host generation");
        }
        contracts.validate("EnvironmentRef", actualEnvironment);
        if (!"game".equals(actualEnvironment.path("kind").asText()) || !"server".equals(actualEnvironment.path("side").asText())) {
            throw failure("INTERFACE_MISMATCH", "Compatibility registration requires an actual game server");
        }
        runtime = actualRuntime; environment = actualEnvironment.deepCopy(); registryGeneration = actualRegistryGeneration;
        try {
            for (ApprovedProfile approval : approvals) {
                checkCurrent(approval);
                ResolvedTarget resolved = resolver.resolve(approval);
                if (resolved == null) throw failure("SOURCE_UNAPPROVED", "Approved compatibility mod is not loaded or observable");
                if (!approval.artifactDigest().equals(resolved.artifact().sha256())) {
                    throw failure("SOURCE_CHANGED", "Loaded compatibility artifact differs from its independent approval pin");
                }
                PublicJavaAdapter.ProfileApproval source = approval(approval, resolved);
                CompatibilityInterfaceProbe probe = CompatibilityInterfaceProbe.detect(contracts, approval.rawProfile(),
                        approval.profileDigest(), approval.approvedProfileRef(), approval.allowedInterfaceDigest(),
                        resolved.artifact(), resolved.loader(), resolved.classApproval(), resolved.target(), source, environment);
                try {
                    if (registering.putIfAbsent(probe.bindingId(), probe) != null
                            || registered.values().stream().anyMatch(value -> value.bindingId().equals(probe.bindingId()))) {
                        throw failure("PROFILE_UNAPPROVED", "Two approval references cannot claim the same compatibility binding");
                    }
                    actualRuntime.registerProvider(probe.registrationDescriptor());
                    probe.register((descriptor, handler, callbacks) -> actualRuntime.register(probe.bindingId(), descriptor, handler, callbacks));
                    probe.inspect(registeredProvider(probe.bindingId()), environment);
                    checkCurrent(approval);
                    registered.put(approval.approvedProfileRef(), probe);
                } catch (RuntimeException exception) { probe.close(); throw exception; }
                finally { registering.remove(probe.bindingId(), probe); }
            }
        } catch (RuntimeException exception) { close(); throw exception; }
    }

    /** Metadata registration has no executable source admission and always installs denial callbacks. */
    void registerMetadataBeforeFreeze(HostRuntime actualRuntime, ObjectNode actualEnvironment,
                                      String actualRegistryGeneration, MetadataTargetResolver resolver) {
        if (closed || runtime != null || actualRuntime == null || resolver == null || actualEnvironment == null
                || actualRegistryGeneration == null || !actualRegistryGeneration.matches("0|[1-9][0-9]*")) {
            throw failure("REGISTRATION_CLOSED", "Metadata registration requires one current open host generation");
        }
        contracts.validate("EnvironmentRef", actualEnvironment);
        if (!"game".equals(actualEnvironment.path("kind").asText()) || !"server".equals(actualEnvironment.path("side").asText())) {
            throw failure("INTERFACE_MISMATCH", "Metadata registration requires the actual game server environment");
        }
        runtime = actualRuntime; environment = actualEnvironment.deepCopy(); registryGeneration = actualRegistryGeneration;
        Map<String, CompatibilityInterfaceProbe.MetadataProbe> prepared = new LinkedHashMap<>();
        try {
            for (ApprovedProfile approval : approvals) {
                checkCurrent(approval); ResolvedMetadataTarget resolved;
                try { resolved = resolver.resolve(approval); }
                catch (ContractException unavailable) {
                    checkMetadataFailureCurrent(approval, unavailable);
                    if ("METADATA_UNAVAILABLE".equals(unavailable.code())) { rememberMetadataUnavailable(approval, unavailable); continue; }
                    throw unavailable;
                }
                checkCurrent(approval);
                if (resolved == null) { metadataUnavailableReasons.put(approval.approvedProfileRef(), "METADATA_SOURCE_UNSUPPORTED"); continue; }
                if (!approval.artifactDigest().equals(resolved.artifact().sha256())) {
                    throw failure("SOURCE_CHANGED", "Metadata artifact differs from its independent protected source pin");
                }
                CompatibilityInterfaceProbe.MetadataProbe probe;
                try {
                    probe = CompatibilityInterfaceProbe.inspectMetadata(contracts, approval.rawProfile(), approval.profileDigest(),
                            approval.approvedProfileRef(), approval.allowedInterfaceDigest(), resolved.artifact(), resolved.loader(),
                            resolved.target(), metadataApproval(approval, resolved), environment);
                } catch (ContractException unavailable) {
                    checkMetadataFailureCurrent(approval, unavailable);
                    if (unavailable.code() != null && Set.of("METADATA_UNAVAILABLE", "UNSUPPORTED_BINDING", "INTERFACE_MISMATCH", "CLASSLOADER_MISMATCH").contains(unavailable.code())) {
                        rememberMetadataUnavailable(approval, unavailable); continue;
                    }
                    throw unavailable;
                }
                prepared.put(approval.approvedProfileRef(), probe);
            }
            ObjectNode baseline = actualRuntime.inventory();
            try { preflightMetadataRegistration(baseline, prepared); }
            catch (ContractException limit) {
                if (!"REGISTRATION_LIMIT".equals(limit.code())) throw limit;
                // No Registrar mutation has happened. Keep native providers and explicit reasons,
                // discard every proposed metadata provider, and still run current/source checks.
                for (var entry : prepared.entrySet()) {
                    ApprovedProfile approval = approvals.stream().filter(value -> value.approvedProfileRef().equals(entry.getKey())).findFirst().orElseThrow();
                    ContractException unavailable = failure("METADATA_UNAVAILABLE", "Metadata additions exceed the current native registration capacity");
                    unavailable.addSuppressed(limit); rememberMetadataUnavailable(approval, unavailable); entry.getValue().close();
                }
                prepared.clear();
            }
            for (var probe : prepared.values()) probe.checkCurrent();
            resolver.checkCurrentSources(); for (ApprovedProfile approval : approvals) checkCurrent(approval);
            if (!baseline.equals(actualRuntime.inventory())) throw failure("REGISTRATION_CHANGED", "Actual registration generation changed during metadata collection");
            for (var entry : prepared.entrySet()) {
                CompatibilityInterfaceProbe.MetadataProbe probe = entry.getValue();
                try {
                    if (metadataRegistering.putIfAbsent(probe.bindingId(), probe) != null
                            || metadataRegistered.values().stream().anyMatch(value -> value.bindingId().equals(probe.bindingId()))) {
                        throw failure("PROFILE_UNAPPROVED", "Two approval references cannot claim one metadata binding");
                    }
                    actualRuntime.registerProvider(probe.registrationDescriptor());
                    probe.registerUnavailable((descriptor, handler, callbacks) -> actualRuntime.register(probe.bindingId(), descriptor, handler, callbacks));
                    probe.inspect(registeredProvider(probe.bindingId()), environment);
                    metadataRegistered.put(entry.getKey(), probe);
                } catch (RuntimeException failure) { probe.close(); throw failure; }
                finally { metadataRegistering.remove(probe.bindingId(), probe); }
            }
            for (ApprovedProfile approval : approvals) checkCurrent(approval);
        } catch (RuntimeException failure) {
            prepared.values().forEach(CompatibilityInterfaceProbe.MetadataProbe::close); close(); throw failure;
        }
    }

    private void checkMetadataFailureCurrent(ApprovedProfile approval, ContractException original) {
        try { checkCurrent(approval); }
        catch (RuntimeException current) {
            if (current != original) original.addSuppressed(current);
            // A currentness failure never becomes an optional metadata-unavailable record.
            throw original;
        }
        // Only the resolver's single, static structural source cause may accompany an optional
        // failure. An already observed currentness/control failure is fatal even if a later probe
        // happens to succeed; do not downgrade its history to an unsupported profile.
        for (Throwable cause : original.getSuppressed()) {
            if (!(cause instanceof ContractException typed) || typed.getSuppressed().length != 0 || typed.code() == null
                    || !Set.of("SOURCE_LIMIT", "SOURCE_INVALID", "SOURCE_UNAVAILABLE", "SOURCE_UNAPPROVED").contains(typed.code())) throw original;
        }
    }

    private void preflightMetadataRegistration(ObjectNode baseline, Map<String, CompatibilityInterfaceProbe.MetadataProbe> prepared) {
        contracts.validate("ProviderInventory", baseline);
        int providerCount = baseline.path("providers").size(); int actionCount = 0; long descriptorBytes = 0;
        var bindings = new java.util.HashSet<String>();
        for (JsonNode existing : baseline.path("providers")) {
            ObjectNode provider = ContractJson.object(existing).deepCopy();
            if (!bindings.add(provider.path("bindingId").asText())) throw failure("REGISTRATION_CHANGED", "Actual baseline contains duplicate binding IDs");
            for (JsonNode action : provider.path("actions")) { descriptorBytes += descriptorBytes(action); actionCount++; }
            provider.putArray("actions"); descriptorBytes += descriptorBytes(provider);
        }
        for (var probe : prepared.values()) {
            if (!bindings.add(probe.bindingId())) throw failure("PROFILE_UNAPPROVED", "Metadata binding collides with an actual or another proposed binding");
            providerCount++; actionCount++;
            descriptorBytes += descriptorBytes(probe.registrationDescriptor());
            descriptorBytes += descriptorBytes(probe.providerDescriptor().path("actions").get(0));
        }
        if (providerCount > 128 || actionCount > 1024 || descriptorBytes > 8L * 1024 * 1024) {
            throw failure("REGISTRATION_LIMIT", "Metadata additions exceed the actual host registration capacity");
        }
    }
    private static int descriptorBytes(JsonNode value) {
        int bytes = ContractJson.bytes(value).length;
        if (bytes > 64 * 1024) throw failure("REGISTRATION_LIMIT", "Metadata descriptor exceeds the actual host descriptor limit");
        return bytes;
    }

    /** Private diagnostic only; this does not alter the public descriptor or make an unsupported profile ready. */
    String metadataUnavailableReason(String approvedProfileRef) { return metadataUnavailableReasons.get(approvedProfileRef); }
    List<String> metadataUnavailableCauseCodes(String approvedProfileRef) { return metadataUnavailableCauses.getOrDefault(approvedProfileRef, List.of()); }
    private void rememberMetadataUnavailable(ApprovedProfile approval, ContractException unavailable) {
        metadataUnavailableReasons.put(approval.approvedProfileRef(), unavailable.code());
        var codes = new java.util.ArrayList<String>(); Throwable[] causes = unavailable.getSuppressed();
        for (int index = 0; index < Math.min(4, causes.length); index++) {
            if (causes[index] instanceof ContractException cause && cause.code() != null && cause.code().matches("[A-Z][A-Z0-9_]{0,127}")) codes.add(cause.code());
        }
        metadataUnavailableCauses.put(approval.approvedProfileRef(), List.copyOf(codes));
    }

    /** No profile installation, method invocation, receiver creation or registry mutation occurs here. */
    ObjectNode inspect(HostRuntime actualRuntime, ObjectNode actualEnvironment,
                       String actualRegistryGeneration, ObjectNode request) {
        HostDispatcher.exactFields(request, Set.of("kind", "profileDigest", "approvedProfileRef"));
        if (!"compatibility_interface".equals(HostDispatcher.string(request, "kind"))) {
            throw failure("INSPECTION_UNSUPPORTED", "Compatibility inspection kind differs");
        }
        checkGeneration(actualRuntime, actualEnvironment, actualRegistryGeneration);
        String reference = HostDispatcher.string(request, "approvedProfileRef");
        String profileDigest = HostDispatcher.string(request, "profileDigest");
        if (!reference.matches("[A-Za-z0-9_.:-]{1,256}") || !digest(profileDigest)) throw failure("PROFILE_UNAPPROVED", "Compatibility approval locators are invalid");
        ApprovedProfile approval = approvals.stream().filter(value -> value.approvedProfileRef().equals(reference) && value.profileDigest().equals(profileDigest)).findFirst()
                .orElseThrow(() -> failure("PROFILE_UNAPPROVED", "No retained native-owner approval matches these exact locators"));
        checkCurrent(approval);
        CompatibilityInterfaceProbe.MetadataProbe metadata = metadataRegistered.get(reference);
        if (metadata != null) {
            ObjectNode result = metadata.inspect(registeredProvider(metadata.bindingId()), actualEnvironment);
            checkGeneration(actualRuntime, actualEnvironment, actualRegistryGeneration); checkCurrent(approval); return result;
        }
        CompatibilityInterfaceProbe probe = registered.get(reference);
        if (probe == null || !probe.profileDigest().equals(profileDigest)) {
            throw failure("COMPATIBILITY_SOURCE_UNAVAILABLE", "Retained compatibility source has no supported actual metadata registration");
        }
        checkCurrent(approval);
        ObjectNode result = probe.inspect(registeredProvider(probe.bindingId()), actualEnvironment);
        checkGeneration(actualRuntime, actualEnvironment, actualRegistryGeneration); checkCurrent(approval);
        return result;
    }

    /**
     * A retained owner approval is not an installed Java source. The host first checks its actual
     * route, environment, generation and permissions; this path can only report that missing resolver.
     */
    void inspectUnavailable(ObjectNode request) {
        if (closed || runtime != null || request == null) throw failure("PROFILE_UNAPPROVED", "No uninstalled compatibility approval generation is current");
        String reference; String profileDigest;
        try {
            HostDispatcher.exactFields(request, Set.of("kind", "profileDigest", "approvedProfileRef"));
            if (!"compatibility_interface".equals(HostDispatcher.string(request, "kind"))) {
                throw failure("PROFILE_UNAPPROVED", "Compatibility inspection kind differs");
            }
            reference = HostDispatcher.string(request, "approvedProfileRef");
            profileDigest = HostDispatcher.string(request, "profileDigest");
            if (!reference.matches("[A-Za-z0-9_.:-]{1,256}") || !digest(profileDigest)) {
                throw failure("PROFILE_UNAPPROVED", "Compatibility approval locators are invalid");
            }
        } catch (ContractException exception) {
            throw failure("PROFILE_UNAPPROVED", "Compatibility inspection requires exact retained approval locators");
        }
        if (approvals.stream().noneMatch(value -> value.approvedProfileRef().equals(reference) && value.profileDigest().equals(profileDigest))) {
            throw failure("PROFILE_UNAPPROVED", "No retained native-owner approval matches these exact locators");
        }
        throw failure("COMPATIBILITY_SOURCE_UNAVAILABLE", "Actual loaded Java definition resolver is not installed for this host generation");
    }

    /** Exact origin/action admission helper for the host RegistrationApproval closure. */
    void checkRegistration(String bindingId, ObjectNode descriptor) {
        if (closed || environment == null) throw failure("PROFILE_UNAPPROVED", "Compatibility approvals are not installed for a host generation");
        CompatibilityInterfaceProbe.MetadataProbe metadata = metadataRegistering.get(bindingId);
        if (metadata == null) metadata = metadataRegistered.values().stream().filter(value -> value.bindingId().equals(bindingId)).findFirst().orElse(null);
        if (metadata != null) {
            metadata.checkCurrent();
            ObjectNode expected = descriptor.has("providerId") ? metadata.registrationDescriptor()
                    : ContractJson.object(metadata.providerDescriptor().path("actions").get(0));
            if (!expected.equals(descriptor)) throw failure("ACTION_UNAPPROVED", "Metadata registration differs from its exact unavailable binding");
            return;
        }
        CompatibilityInterfaceProbe probe = registering.get(bindingId);
        if (probe == null) probe = registered.values().stream().filter(value -> value.bindingId().equals(bindingId)).findFirst().orElse(null);
        if (probe == null) throw failure("PROFILE_UNAPPROVED", "Compatibility binding was not detected from a protected owner approval");
        probe.checkCurrent();
        ObjectNode expected = descriptor.has("providerId") ? probe.registrationDescriptor()
                : ContractJson.object(probe.providerDescriptor().path("actions").get(0));
        if (!expected.equals(descriptor)) throw failure("ACTION_UNAPPROVED", "Compatibility registration differs from its exact detected binding");
    }

    private CompatibilityInterfaceProbe.MetadataApproval metadataApproval(ApprovedProfile expected, ResolvedMetadataTarget resolved) {
        return new CompatibilityInterfaceProbe.MetadataApproval() {
            @Override public void checkProfile(ObjectNode profile, String profileDigest, String artifactDigest,
                                               PublicJavaAdapter.RuntimeTarget actualTarget) {
                checkpoint();
                if (!expected.profileDigest().equals(profileDigest) || !expected.artifactDigest().equals(artifactDigest)
                        || !resolved.target().equals(actualTarget)) throw failure("PROFILE_UNAPPROVED", "Metadata approval source pins differ");
                resolved.currentMetadataApproval().checkProfile(profile, profileDigest, artifactDigest, actualTarget); checkpoint();
            }
            @Override public void checkInterface(ObjectNode support, ApprovedArtifact.ClassMetadata actualClass) {
                checkpoint();
                if (!expected.artifactDigest().equals(actualClass.jarSha256()) || actualClass.actualClass().getClassLoader() != resolved.loader()) {
                    throw failure("SOURCE_CHANGED", "Actual metadata class source or loader changed");
                }
                resolved.currentMetadataApproval().checkInterface(support, actualClass); checkpoint();
            }
            @Override public void checkCurrent(String profileDigest, String artifactDigest, Class<?> actualClass) {
                checkpoint();
                if (!expected.profileDigest().equals(profileDigest) || !expected.artifactDigest().equals(artifactDigest)
                        || actualClass.getClassLoader() != resolved.loader()) throw failure("SOURCE_CHANGED", "Current metadata source pins changed");
                resolved.currentMetadataApproval().checkCurrent(profileDigest, artifactDigest, actualClass); checkpoint();
            }
            @Override public void checkpoint() {
                NativeCompatibilityApprovals.this.checkCurrent(expected); resolved.currentMetadataApproval().checkpoint();
            }
        };
    }

    private PublicJavaAdapter.ProfileApproval approval(ApprovedProfile expected, ResolvedTarget resolved) {
        return new PublicJavaAdapter.ProfileApproval() {
            @Override public void checkProfile(ObjectNode profile, String profileDigest, String artifactDigest,
                                               PublicJavaAdapter.RuntimeTarget actualTarget) {
                NativeCompatibilityApprovals.this.checkCurrent(expected);
                if (!expected.profileDigest().equals(profileDigest) || !expected.artifactDigest().equals(artifactDigest)
                        || !resolved.target().equals(actualTarget)) throw failure("PROFILE_UNAPPROVED", "Actual compatibility source pins differ");
                resolved.currentSourceApproval().checkProfile(profile, profileDigest, artifactDigest, actualTarget);
            }
            @Override public void checkInterface(ObjectNode support, ApprovedArtifact.ClassObservation actualClass) {
                NativeCompatibilityApprovals.this.checkCurrent(expected);
                if (!expected.artifactDigest().equals(actualClass.jarSha256())) throw failure("SOURCE_CHANGED", "Observed compatibility class artifact changed");
                resolved.currentSourceApproval().checkInterface(support, actualClass);
            }
            @Override public void checkCurrent(String profileDigest, String artifactDigest, Class<?> actualClass) {
                NativeCompatibilityApprovals.this.checkCurrent(expected);
                if (!expected.profileDigest().equals(profileDigest) || !expected.artifactDigest().equals(artifactDigest)
                        || actualClass.getClassLoader() != resolved.loader()) throw failure("SOURCE_CHANGED", "Registered compatibility class or source pin changed");
                resolved.currentSourceApproval().checkCurrent(profileDigest, artifactDigest, actualClass);
                ApprovedArtifact.ClassObservation observed = resolved.artifact().observe(actualClass.getName(), resolved.loader(), resolved.classApproval());
                if (observed.actualClass() != actualClass) throw failure("SOURCE_CHANGED", "Registered compatibility class identity changed");
            }
        };
    }

    private ObjectNode registeredProvider(String bindingId) {
        ObjectNode found = null;
        for (JsonNode provider : runtime.inventory().path("providers")) if (bindingId.equals(provider.path("bindingId").asText())) {
            if (found != null) throw failure("REGISTRATION_CHANGED", "Actual compatibility inventory contains a duplicate binding");
            found = ContractJson.object(provider).deepCopy();
        }
        if (found == null) throw failure("REGISTRATION_CHANGED", "Actual compatibility registration is missing");
        return found;
    }
    private void checkCurrent(ApprovedProfile profile) {
        if (closed || runtime == null || environment == null) throw failure("PROFILE_UNAPPROVED", "Compatibility generation is not current");
        currentApproval.check(profile, environment.deepCopy(), registryGeneration);
    }
    private void checkGeneration(HostRuntime actualRuntime, ObjectNode actualEnvironment, String actualRegistryGeneration) {
        if (closed || runtime == null || runtime != actualRuntime || !environment.equals(actualEnvironment)
                || !registryGeneration.equals(actualRegistryGeneration)) throw failure("TARGET_DRIFT", "Compatibility host epoch or registry generation changed");
    }
    @Override public void close() {
        closed = true; registered.values().forEach(CompatibilityInterfaceProbe::close); registered.clear();
        registering.values().forEach(CompatibilityInterfaceProbe::close); registering.clear();
        metadataRegistered.values().forEach(CompatibilityInterfaceProbe.MetadataProbe::close); metadataRegistered.clear();
        metadataRegistering.values().forEach(CompatibilityInterfaceProbe.MetadataProbe::close); metadataRegistering.clear();
        metadataUnavailableReasons.clear();
        metadataUnavailableCauses.clear();
    }
    private static boolean digest(String value) { return value != null && value.matches("[a-f0-9]{64}"); }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
}
