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

    private final ContractJson contracts;
    private final List<ApprovedProfile> approvals;
    private final CurrentApproval currentApproval;
    private final Map<String, CompatibilityInterfaceProbe> registered = new LinkedHashMap<>();
    private final Map<String, CompatibilityInterfaceProbe> registering = new LinkedHashMap<>();
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
        CompatibilityInterfaceProbe probe = registered.get(reference);
        if (probe == null || !probe.profileDigest().equals(profileDigest)) {
            throw failure("PROFILE_UNAPPROVED", "No current registered native-owner approval matches these exact locators");
        }
        ApprovedProfile approval = approvals.stream().filter(value -> value.approvedProfileRef().equals(reference)).findFirst().orElseThrow();
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
        CompatibilityInterfaceProbe probe = registering.get(bindingId);
        if (probe == null) probe = registered.values().stream().filter(value -> value.bindingId().equals(bindingId)).findFirst().orElse(null);
        if (probe == null) throw failure("PROFILE_UNAPPROVED", "Compatibility binding was not detected from a protected owner approval");
        probe.checkCurrent();
        ObjectNode expected = descriptor.has("providerId") ? probe.registrationDescriptor()
                : ContractJson.object(probe.providerDescriptor().path("actions").get(0));
        if (!expected.equals(descriptor)) throw failure("ACTION_UNAPPROVED", "Compatibility registration differs from its exact detected binding");
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
    }
    private static boolean digest(String value) { return value != null && value.matches("[a-f0-9]{64}"); }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
}
