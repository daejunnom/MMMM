package io.github.daejunnom.mmmm.javaadapter;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Registrar;
import java.util.Map;
import java.util.Set;

/** Exact readonly public-Java metadata for one externally approved local profile. */
public final class CompatibilityInterfaceProbe implements AutoCloseable {
    public static final int MAX_PROFILE_BYTES = 64 * 1024;
    private final ContractJson contracts;
    private final PublicJavaAdapter.Candidate candidate;
    private final PublicJavaAdapter.ProfileApproval approval;
    private final ApprovedArtifact artifact;
    private final ClassLoader loader;
    private final ApprovedArtifact.LoadedClassApproval classApproval;
    private final ApprovedArtifact.ClassObservation observedClass;
    private final ObjectNode environment;
    private final ObjectNode observedInterface;
    private final ObjectNode provider;
    private final String approvedProfileRef;
    private final String interfaceDigest;
    private boolean closed;

    private CompatibilityInterfaceProbe(ContractJson contracts, PublicJavaAdapter.Candidate candidate,
                                        PublicJavaAdapter.ProfileApproval approval, ApprovedArtifact artifact,
                                        ClassLoader loader, ApprovedArtifact.LoadedClassApproval classApproval,
                                        ApprovedArtifact.ClassObservation observedClass, ObjectNode environment,
                                        ObjectNode observedInterface, ObjectNode provider,
                                        String approvedProfileRef, String interfaceDigest) {
        this.contracts = contracts; this.candidate = candidate; this.approval = approval; this.artifact = artifact;
        this.loader = loader; this.classApproval = classApproval; this.observedClass = observedClass;
        this.environment = environment.deepCopy(); this.observedInterface = observedInterface.deepCopy();
        this.provider = provider.deepCopy(); this.approvedProfileRef = approvedProfileRef;
        this.interfaceDigest = interfaceDigest;
    }

    /**
     * This input is not an approval issuer. The trusted native composition must obtain the raw bytes,
     * three independent pins and approval callback from its protected owner policy before calling it.
     * Detection neither registers a handler nor calls the selected API or initializes its class.
     */
    public static CompatibilityInterfaceProbe detect(ContractJson contracts, byte[] rawProfile,
            String expectedProfileDigest, String approvedProfileRef, String allowedInterfaceDigest,
            ApprovedArtifact artifact, ClassLoader loader, ApprovedArtifact.LoadedClassApproval classApproval,
            PublicJavaAdapter.RuntimeTarget target, PublicJavaAdapter.ProfileApproval approval,
            ObjectNode environment) {
        if (contracts == null || environment == null || rawProfile == null || rawProfile.length == 0 || rawProfile.length > MAX_PROFILE_BYTES
                || !digest(expectedProfileDigest) || !digest(allowedInterfaceDigest)
                || approvedProfileRef == null || approvedProfileRef.isEmpty() || approvedProfileRef.length() > 4096
                || artifact == null || loader == null || classApproval == null || approval == null || target == null) {
            throw failure("PROFILE_UNAPPROVED", "Bounded raw profile and separate trusted approval pins are required");
        }
        ObjectNode profile = ContractJson.object(ContractJson.parse(rawProfile.clone()));
        contracts.validate("CompatibilityProfile", profile);
        if (!expectedProfileDigest.equals(ContractJson.digest(profile))) {
            throw failure("PROFILE_UNAPPROVED", "Raw profile differs from its approved semantic digest");
        }
        contracts.validate("EnvironmentRef", environment);
        if (!"game".equals(environment.path("kind").asText()) || !"server".equals(environment.path("side").asText())
                || !"server".equals(target.side())) {
            throw failure("INTERFACE_MISMATCH", "Readonly compatibility requires the actual server environment");
        }
        ObjectNode binding = ContractJson.object(profile.get("binding"));
        ObjectNode action = ContractJson.object(profile.get("action"));
        ObjectNode match = ContractJson.object(profile.get("match"));
        if (target.modId() == null || target.modId().isEmpty() || !exactVersion(target.gameVersion()) || !exactVersion(target.modVersion())) {
            throw failure("INTERFACE_MISMATCH", "Compatibility requires an exact actual mod and game version");
        }
        for (String key : new String[] {"supportedGameVersions", "supportedModVersions"}) for (var version : match.path(key)) {
            if (!exactVersion(version.asText())) throw failure("INTERFACE_MISMATCH", "Compatibility version ranges are unsupported");
        }
        if (!"public_java".equals(binding.path("kind").asText()) || !"static".equals(binding.path("receiver").asText())
                || !"scalar".equals(binding.path("resultCodec").asText())
                || !scalar(binding.path("returnType").asText()) || !"read".equals(action.path("effect").asText())
                || !"synchronous".equals(action.path("completion").asText())
                || !Set.of("pure", "unsupported").contains(action.path("planning").asText())
                || !Set.of("declared", "interface_checked").contains(action.path("versionEvidence").asText())
                || binding.has("receiverHandleType")) {
            throw failure("UNSUPPORTED_BINDING", "Initial compatibility registration supports static synchronous scalar reads only");
        }
        for (var type : binding.path("parameterTypes")) if (!scalar(type.asText())) {
            throw failure("UNSUPPORTED_BINDING", "Readonly compatibility parameters must use the bounded scalar codec");
        }
        for (var mapping : binding.path("arguments")) if ("handle".equals(mapping.path("kind").asText())) {
            throw failure("UNSUPPORTED_BINDING", "Readonly compatibility does not resolve or create scoped handles");
        }
        ApprovedArtifact.ClassObservation[] captured = new ApprovedArtifact.ClassObservation[1];
        ApprovedArtifact.LoadedClassApproval capture = (actual, actualLoader, jarDigest, classDigest) -> {
            classApproval.check(actual, actualLoader, jarDigest, classDigest);
            captured[0] = new ApprovedArtifact.ClassObservation(actual, classDigest, jarDigest);
        };
        PublicJavaAdapter.Candidate candidate = PublicJavaAdapter.detect(contracts, profile, artifact, loader,
                capture, target, approval, new PublicJavaAdapter.Policies(null, Map.of(), true));
        try {
            ObjectNode observed = ContractJson.newObject().put("loader", target.loader())
                    .put("targetGameVersion", target.gameVersion()).put("modVersion", target.modVersion())
                    .put("hostProtocolVersion", ContractJson.VERSION).put("implementationDigest", artifact.sha256())
                    .put("loaded", true).put("connected", true).put("availability", "available");
            observed.set("environment", environment.deepCopy());
            if (target.modId() == null) observed.putNull("modId"); else observed.put("modId", target.modId());
            observed.set("support", candidate.observedSupport());
            observed.putObject("readiness").put("ready", true).putNull("possibleLossCodes");
            String observedInterfaceDigest = interfaceDigest(observed);
            if (!allowedInterfaceDigest.equals(observedInterfaceDigest)) {
                throw failure("INTERFACE_MISMATCH", "Actual public interface differs from its independent approval pin");
            }
            ObjectNode material = ContractJson.newObject().put("kind", "mmmm-compatibility-binding/1")
                    .put("profileDigest", expectedProfileDigest).put("interfaceDigest", observedInterfaceDigest);
            material.set("environment", environment.deepCopy());
            ObjectNode provider = ContractJson.newObject().put("contractVersion", ContractJson.VERSION)
                    .put("providerId", profile.path("profileId").asText()).put("bindingId", "compat-" + ContractJson.digest(material))
                    .put("providerVersion", profile.path("profileVersion").asText()).put("registrationMode", "compatibility")
                    .put("hostProtocolVersion", ContractJson.VERSION).put("compatibilityEvidence", "interface_checked")
                    .put("availability", "available");
            provider.set("environment", environment.deepCopy());
            provider.putObject("origin").put("kind", "local_profile").put("sourceId", approvedProfileRef)
                    .put("sourceDigest", expectedProfileDigest);
            provider.putArray("actions").add(candidate.descriptor()); contracts.validate("ProviderDescriptor", provider);
            return new CompatibilityInterfaceProbe(contracts, candidate, approval, artifact, loader, classApproval,
                    captured[0], environment, observed, provider, approvedProfileRef, observedInterfaceDigest);
        } catch (RuntimeException exception) { candidate.close(); throw exception; }
    }

    /** Rust's InterfaceObservation projection; readiness/connection remain independently current facts. */
    public static String interfaceDigest(ObjectNode observedInterface) {
        ObjectNode material = ContractJson.newObject().put("kind", "mmmm-interface-observation/1")
                .put("side", observedInterface.path("environment").path("side").asText());
        for (String key : new String[] {"loader", "targetGameVersion", "modId", "modVersion", "hostProtocolVersion", "implementationDigest", "support"}) {
            if (!observedInterface.has(key)) throw failure("INTERFACE_MISMATCH", "Observed interface projection is incomplete");
            material.set(key, observedInterface.get(key).deepCopy());
        }
        return ContractJson.digest(material);
    }

    public String approvedProfileRef() { return approvedProfileRef; }
    public String profileDigest() { return candidate.profileDigest(); }
    public String artifactDigest() { return candidate.artifactDigest(); }
    public String interfaceDigest() { return interfaceDigest; }
    public String bindingId() { return provider.path("bindingId").asText(); }
    public ObjectNode providerDescriptor() { return provider.deepCopy(); }
    public ObjectNode registrationDescriptor() { ObjectNode result = providerDescriptor(); result.putArray("actions"); return result; }

    /** Called only by the trusted host while the actual HostRuntime Registrar is still open. */
    public void register(Registrar registrar) { checkCurrent(); candidate.register(registrar); }

    /** Reobserves the exact loaded class and policy without invoking the method or changing a registry. */
    public void checkCurrent() {
        if (closed) throw failure("BINDING_CLOSED", "Readonly compatibility generation has ended");
        approval.checkCurrent(candidate.profileDigest(), artifact.sha256(), observedClass.actualClass());
        ApprovedArtifact.ClassObservation current = artifact.observe(observedClass.actualClass().getName(), loader, classApproval);
        if (current.actualClass() != observedClass.actualClass() || !current.classSha256().equals(observedClass.classSha256())) {
            throw failure("SOURCE_CHANGED", "The exact registered public class definition changed");
        }
    }

    /** Inventory readback must come from this actual host runtime, never the public request. */
    public ObjectNode inspect(ObjectNode registeredProvider, ObjectNode actualEnvironment) {
        checkCurrent();
        contracts.validate("ProviderDescriptor", registeredProvider);
        if (!environment.equals(actualEnvironment) || !provider.equals(registeredProvider)) {
            throw failure("REGISTRATION_CHANGED", "Readonly compatibility no longer matches its actual registered environment and actions");
        }
        ObjectNode result = ContractJson.newObject().put("profileDigest", candidate.profileDigest());
        result.set("registeredProvider", registeredProvider.deepCopy()); result.set("interface", observedInterface.deepCopy());
        return result;
    }

    @Override public void close() { closed = true; candidate.close(); }
    private static boolean digest(String value) { return value != null && value.matches("[a-f0-9]{64}"); }
    private static boolean exactVersion(String value) {
        return value != null && value.length() <= 128 && value.matches("[A-Za-z0-9._+-]+")
                && !Set.of("latest", "main").contains(value);
    }
    private static boolean scalar(String name) {
        return Set.of("java.lang.String", "boolean", "java.lang.Boolean", "int", "java.lang.Integer",
                "float", "java.lang.Float", "double", "java.lang.Double").contains(name);
    }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
}
