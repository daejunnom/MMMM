package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Closed, immutable structural projection of the Rust activation authority.
 * Matching these pins does not establish the source receipt's authenticity, native
 * state, a complete effect closure or an approved producer/profile/generation.
 * Trusted admission must establish those facts independently before installation;
 * the plan approval additionally reserves the actual full Invocation at dispatch.
 * This class performs no game, command, filesystem or CAS access.
 */
public final class NativeActivationApproval {
    public static final int MAX_BYTES = 64 * 1024;
    public static final int MAX_SOURCE_BYTES = 16_384;
    private static final int MAX_TARGETS = 256;
    private static final int MAX_SOURCE_PINS = 4096;
    private static final long MAX_EVIDENCE_BYTES = 8L * 1024 * 1024;
    private static final long MAX_EXACT_INTEGER = 9_007_199_254_740_991L;
    private static final String ID = "[a-z0-9][a-z0-9._:-]{0,127}";
    private static final String SHA = "[a-f0-9]{64}";
    private static final Set<String> FIELDS = Set.of("format", "planHash", "stepId", "actionDigest",
            "implementationDigest", "argumentsDigest", "preparedChangeSha256", "contextId", "contextDigest",
            "policyRevision", "targetProfileId", "targetProfileDigest", "targetArtifactDigest", "compilerDigest",
            "codecDigest", "producerDigest", "registryGeneration", "nativeSourceReceipt", "targetEvidenceResources",
            "activationStepIndex", "sourceDataStepIndex", "nativeStepDigest", "commandDigest", "sourceBodySha256",
            "sourceBodyByteLength", "sourceObjectId", "sourceRevision", "instanceId", "ownerPrefabId",
            "sourceObjectPins", "sourceResourcePins", "effectSelectors");
    private static final Set<String> DIGESTS = Set.of("planHash", "actionDigest", "implementationDigest",
            "argumentsDigest", "preparedChangeSha256", "contextDigest", "policyRevision", "targetProfileDigest",
            "targetArtifactDigest", "compilerDigest", "codecDigest", "producerDigest", "nativeStepDigest",
            "commandDigest", "sourceBodySha256", "sourceRevision");
    private static final Set<String> OBJECT_KINDS = Set.of("prefab", "instance", "command_module", "clip",
            "asset", "physics_definition");
    private final ContractJson contracts;
    private final ObjectNode proof;

    public NativeActivationApproval(ContractJson contracts, ObjectNode value) {
        this.contracts = Objects.requireNonNull(contracts);
        byte[] bytes = ContractJson.bytes(Objects.requireNonNull(value));
        if (bytes.length > MAX_BYTES) throw invalid("Activation proof exceeds its byte limit");
        proof = ContractJson.object(ContractJson.parse(bytes));
        exact(proof, FIELDS);
        require("mmmm.activation-authority/1".equals(text(proof, "format")), "Activation proof format differs");
        DIGESTS.forEach(field -> sha(proof, field));
        for (String field : Set.of("stepId", "contextId", "targetProfileId", "sourceObjectId", "instanceId", "ownerPrefabId")) id(proof, field);
        require(boundedText(proof, "registryGeneration", 128).getBytes(StandardCharsets.UTF_8).length <= 128,
                "Activation registry generation exceeds its byte limit");
        integer(proof.path("activationStepIndex"), 0, 16_383);
        integer(proof.path("sourceDataStepIndex"), 0, 16_383);
        require(integer(proof.path("activationStepIndex"), 0, 16_383)
                != integer(proof.path("sourceDataStepIndex"), 0, 16_383), "Source and activation indices cannot identify the same compiler step");
        integer(proof.path("sourceBodyByteLength"), 1, MAX_SOURCE_BYTES);
        ObjectNode receipt = ContractJson.object(proof.path("nativeSourceReceipt"));
        exact(receipt, Set.of("digest", "byteLength")); sha(receipt, "digest");
        integer(receipt.path("byteLength"), 1, MAX_EVIDENCE_BYTES);

        Map<String, ObjectNode> sourceResources = resourcePins("sourceResourcePins", 0, MAX_SOURCE_PINS);
        Map<String, ObjectNode> evidenceResources = resourcePins("targetEvidenceResources", 1, MAX_TARGETS);
        for (Map.Entry<String, ObjectNode> entry : evidenceResources.entrySet()) {
            require(sameJson(entry.getValue(), sourceResources.get(entry.getKey())), "Target evidence is not an exact source resource pin");
            integer(entry.getValue().path("sizeBytes"), 0, MAX_EVIDENCE_BYTES);
        }
        Set<String> ownedPins = new HashSet<>();
        for (JsonNode valuePin : array(proof, "sourceObjectPins", 0, MAX_SOURCE_PINS)) {
            ObjectNode pin = ContractJson.object(valuePin); exact(pin, Set.of("kind", "objectId", "revision"));
            require(OBJECT_KINDS.contains(text(pin, "kind")), "Source object pin kind is unsupported");
            id(pin, "objectId"); sha(pin, "revision");
            require(ownedPins.add(text(pin, "kind") + "\u0000" + text(pin, "objectId")), "Source object pin is duplicated or conflicting");
        }
        Set<String> effectTargets = new HashSet<>();
        for (JsonNode valueEffect : array(proof, "effectSelectors", 1, MAX_TARGETS)) {
            ObjectNode effect = ContractJson.object(valueEffect); exact(effect, Set.of("selector", "access", "resource"));
            ObjectNode selector = effectSelector(effect.path("selector"));
            require(Set.of("read", "write", "read_write").contains(text(effect, "access")), "Activation access is unsupported");
            ObjectNode resource = resource(effect.path("resource"));
            require(text(selector, "resourceId").equals(text(resource, "resourceId")), "Effect resource differs from its exact selector association");
            ObjectNode semanticTarget = selector.deepCopy(); semanticTarget.remove("resourceId");
            require(effectTargets.add(ContractJson.digest(semanticTarget)), "Activation effect target is duplicated or conflicting");
        }
    }

    public ObjectNode snapshot() { return proof.deepCopy(); }

    /** Match compiler content, never an index in a phase-selected subset. */
    public boolean matches(ObjectNode sealedNativeStep) {
        return text(proof, "nativeStepDigest").equals(originalNativeStepDigest(sealedNativeStep));
    }

    /** The extra bridge commandDigest is excluded from the original compiler's seven fields. */
    public static String originalNativeStepDigest(ObjectNode sealedNativeStep) {
        ObjectNode step = Objects.requireNonNull(sealedNativeStep).deepCopy();
        NativePlanApproval.validateSealedNativeStep(step);
        step.remove("commandDigest");
        return ContractJson.digest(step);
    }

    /** Validate all pins available in the private frozen plan and native projection. */
    public void validateBindings(ObjectNode manifest, ObjectNode planStep, ObjectNode nativeExecution) {
        Objects.requireNonNull(manifest); Objects.requireNonNull(planStep); Objects.requireNonNull(nativeExecution);
        compare(manifest, "planHash"); compare(manifest, "policyRevision");
        for (String field : Set.of("stepId", "actionDigest", "implementationDigest", "argumentsDigest", "contextId", "contextDigest")) compare(planStep, field);
        for (String field : Set.of("stepId", "argumentsDigest", "preparedChangeSha256", "targetProfileId", "targetArtifactDigest", "compilerDigest", "codecDigest")) compare(nativeExecution, field);
        require("activate".equals(text(nativeExecution, "phase")), "Activation proof belongs to a different execution phase");
        require("mmmm.native-scene-command/1".equals(text(nativeExecution, "format")), "Native execution format differs");
        ObjectNode scope = ContractJson.object(nativeExecution.path("targetScope")); contracts.validate("Scope", scope);
        require(text(scope, "projectId").equals(text(manifest, "projectId")), "Activation scope differs from its approval project");
        int pinMatches = 0;
        for (JsonNode valuePin : array(manifest, "contextPins", 1, MAX_TARGETS)) {
            contracts.validate("ContextPin", valuePin); ObjectNode pin = ContractJson.object(valuePin);
            if (text(proof, "contextId").equals(text(pin, "contextId"))) {
                compare(pin, "contextDigest");
                require("game".equals(pin.path("environment").path("kind").asText())
                        && "server".equals(pin.path("environment").path("side").asText()), "Activation requires a server game context");
                pinMatches++;
            }
        }
        require(pinMatches == 1, "Activation context lacks one exact frozen pin");
        if (planStep.has("arguments")) {
            require(text(proof, "argumentsDigest").equals(ContractJson.digest(planStep.path("arguments"))), "Original plan arguments changed");
            ObjectNode prepared = resource(planStep.path("arguments").path("preparedChange"));
            require(text(proof, "preparedChangeSha256").equals(text(prepared, "sha256")), "Original prepared change pin changed");
        }

        ObjectNode selected = null;
        for (JsonNode valueStep : array(nativeExecution, "steps", 1, MAX_TARGETS)) {
            ObjectNode step = ContractJson.object(valueStep);
            if (matches(step)) {
                require(selected == null, "Activation compiler step occurs more than once in its selected execution");
                selected = step;
            }
        }
        require(selected != null, "Activation compiler step is absent from the selected execution");
        require("activate".equals(text(selected, "phase"))
                && "command_activation".equals(selected.path("instruction").path("kind").asText()), "Proof does not identify a native activation instruction");
        require(text(proof, "commandDigest").equals(text(selected, "commandDigest"))
                && text(proof, "commandDigest").equals(ContractJson.digest(selected.path("encoded_commands"))), "Activation command bytes changed");
        for (Map.Entry<String, String> field : Map.of("sourceObjectId", "source_object_id", "instanceId", "instance_id", "ownerPrefabId", "owner_prefab_id").entrySet()) {
            require(text(proof, field.getKey()).equals(text(selected, field.getValue())), "Activation source identity changed");
        }
        validateFootprints(planStep, nativeExecution, scope);
        validateControlFootprints(planStep, nativeExecution, ContractJson.object(selected.path("instruction")));
        validateSourcePreconditions(planStep);
    }

    /** Also bind the available installed original context; live admission remains separate. */
    public void validateBindings(ObjectNode manifest, ObjectNode planStep, ObjectNode nativeExecution, ObjectNode context) {
        validateBindings(manifest, planStep, nativeExecution);
        contracts.validate("ExecutionContext", context);
        for (String field : Set.of("contextId", "contextDigest", "policyRevision")) compare(context, field);
        require(text(proof, "contextDigest").equals(ContractJson.contextDigest(context)), "Installed context digest changed");
        require(text(manifest, "principalId").equals(text(context, "principalRef"))
                && text(manifest, "projectId").equals(text(context, "projectId")), "Installed activation owner or project changed");
        require("game".equals(context.path("environment").path("kind").asText())
                && "server".equals(context.path("environment").path("side").asText()), "Installed context is not a server game context");
        for (JsonNode valuePin : manifest.path("contextPins")) {
            if (text(proof, "contextId").equals(valuePin.path("contextId").asText())) {
                require(sameJson(valuePin.path("environment"), context.path("environment")), "Installed game environment changed");
            }
        }
        for (JsonNode valueEffect : proof.path("effectSelectors")) {
            String resourceId = valueEffect.path("resource").path("resourceId").asText();
            require(contains(context.path("scope").path("resourceIds"), resourceId), "Activation effect exceeds the installed resource scope");
        }
    }

    /** Compare unchanged actual UTF-8 bytes; a matching hash does not authenticate their producer. */
    public void validateSourceBytes(byte[] exactUtf8) {
        Objects.requireNonNull(exactUtf8);
        require(exactUtf8.length > 0 && exactUtf8.length <= MAX_SOURCE_BYTES, "Activation source exceeds its byte limit");
        byte[] source = exactUtf8.clone();
        try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(source));
        } catch (CharacterCodingException exception) { throw invalid("Activation source is not valid UTF-8"); }
        require(source.length == integer(proof.path("sourceBodyByteLength"), 1, MAX_SOURCE_BYTES)
                && text(proof, "sourceBodySha256").equals(ContractJson.sha256(source)), "Activation raw source bytes changed");
    }

    private void validateFootprints(ObjectNode planStep, ObjectNode execution, ObjectNode scope) {
        Map<String, ObjectNode> observed = new HashMap<>();
        for (JsonNode valueTarget : array(execution, "observedTargets", 1, MAX_TARGETS)) {
            ObjectNode target = ContractJson.object(valueTarget);
            exact(target, Set.of("selector", "expectedDigest", "expectedPresence", "ownerTag"));
            ObjectNode selector = ContractJson.object(target.path("selector"));
            sha(target, "expectedDigest");
            require(observed.putIfAbsent(ContractJson.digest(selector), target) == null, "Native observed selector is duplicated");
        }
        Map<String, String> associations = new HashMap<>();
        for (JsonNode valueTarget : array(execution, "resourceTargets", 0, MAX_TARGETS)) {
            ObjectNode target = ContractJson.object(valueTarget); exact(target, Set.of("resourceId", "selector"));
            String resourceId = id(target, "resourceId"); String selectorDigest = ContractJson.digest(target.path("selector"));
            require(associations.putIfAbsent(selectorDigest, resourceId) == null, "Native resource association is duplicated or conflicting");
        }
        for (JsonNode valueEffect : proof.path("effectSelectors")) {
            ObjectNode effect = ContractJson.object(valueEffect); ObjectNode selector = ContractJson.object(effect.path("selector"));
            String resourceId = text(selector, "resourceId"); String selectorDigest = ContractJson.digest(selector);
            require(resourceId.equals(associations.get(selectorDigest)) && contains(scope.path("resourceIds"), resourceId), "Activation effect lacks its exact scoped native association");
            ObjectNode target = observed.get(selectorDigest);
            require(target != null && sameJson(target.path("selector"), selector), "Activation effect lacks its exact observed target");
            require(target.path("ownerTag").isNull(), "Activation state effects cannot carry an entity ownership tag");
            require(Set.of("present", "absent").contains(text(target, "expectedPresence")), "Activation effect cannot use an unknown before state");
            String access = text(effect, "access");
            if (!"write".equals(access)) require(resourceMember(planStep.path("resourcesRead"), resourceId), "Activation read effect exceeds the frozen step");
            if (!"read".equals(access)) require(resourceMember(planStep.path("resourcesWritten"), resourceId), "Activation write effect exceeds the frozen step");
            requirePrecondition(planStep, Set.of("resource_hash", "region_snapshot"), "native:" + selectorDigest, text(target, "expectedDigest"));
        }
    }

    private void validateSourcePreconditions(ObjectNode planStep) {
        for (JsonNode valuePin : proof.path("sourceResourcePins")) {
            ObjectNode pin = ContractJson.object(valuePin); String digest = text(pin, "sha256"); String resourceId = text(pin, "resourceId");
            require(resourceMember(planStep.path("resourcesRead"), resourceId), "Activation source resource exceeds the frozen step read dependencies");
            requirePrecondition(planStep, Set.of("resource_hash"), "cas:" + resourceId + ":" + digest, digest);
        }
        for (JsonNode valuePin : proof.path("sourceObjectPins")) {
            ObjectNode pin = ContractJson.object(valuePin); String revision = text(pin, "revision");
            requirePrecondition(planStep, Set.of("object_revision"), "owned:" + text(pin, "kind") + ":" + text(pin, "objectId") + ":" + revision, revision);
        }
    }

    /** Bind both original direct-control captures without asserting their native truth. */
    private void validateControlFootprints(ObjectNode planStep, ObjectNode execution, ObjectNode instruction) {
        for (String kind : Set.of("block_state", "block_entity")) {
            ObjectNode selector = ContractJson.newObject(); selector.put("kind", kind);
            selector.put("dimension", text(instruction, "dimension"));
            selector.set("position", instruction.path("position").deepCopy());
            String selectorDigest = ContractJson.digest(selector); int matches = 0;
            for (JsonNode valueTarget : array(execution, "observedTargets", 1, MAX_TARGETS)) {
                ObjectNode target = ContractJson.object(valueTarget);
                if (sameJson(target.path("selector"), selector)) {
                    require("present".equals(text(target, "expectedPresence")) && target.path("ownerTag").isNull(),
                            "Activation control block needs an exact present untagged before capture");
                    requirePrecondition(planStep, Set.of("resource_hash", "region_snapshot"),
                            "native:" + selectorDigest, sha(target, "expectedDigest"));
                    matches++;
                }
            }
            require(matches == 1, "Activation control block lacks one exact original before capture");
        }
    }

    private void requirePrecondition(ObjectNode planStep, Set<String> kinds, String subject, String expected) {
        int matches = 0;
        for (JsonNode value : array(planStep, "preconditions", 0, MAX_TARGETS)) {
            contracts.validate("Precondition", value); ObjectNode condition = ContractJson.object(value);
            if (kinds.contains(text(condition, "kind")) && subject.equals(text(condition, "subject"))) {
                require(expected.equals(text(condition, "expected")) && "full_target".equals(text(condition, "coverage")), "Activation precondition is changed or incomplete");
                matches++;
            }
        }
        require(matches == 1, "Activation source or effect lacks one exact full-target precondition");
    }

    private Map<String, ObjectNode> resourcePins(String field, int min, int max) {
        Map<String, ObjectNode> result = new HashMap<>();
        for (JsonNode value : array(proof, field, min, max)) {
            ObjectNode resource = resource(value);
            require(result.putIfAbsent(text(resource, "resourceId"), resource) == null, "Resource pin is duplicated or conflicting");
        }
        return result;
    }

    private ObjectNode resource(JsonNode value) {
        contracts.validate("ResourceRef", value); ObjectNode resource = ContractJson.object(value);
        integer(resource.path("sizeBytes"), 0, MAX_EXACT_INTEGER); return resource;
    }

    private void compare(ObjectNode value, String field) {
        require(text(proof, field).equals(text(value, field)), "Activation approval pin changed");
    }

    private static ObjectNode effectSelector(JsonNode value) {
        ObjectNode selector = ContractJson.object(value); String kind = text(selector, "kind");
        switch (kind) {
            case "score" -> {
                exact(selector, Set.of("kind", "objective", "holder", "resourceId"));
                for (String field : Set.of("objective", "holder")) {
                    require(boundedText(selector, field, 128).matches("[A-Za-z0-9_.#-]+"), "Activation score target is not a finite literal name");
                }
            }
            case "storage" -> {
                exact(selector, Set.of("kind", "storage", "key", "resourceId"));
                require(boundedText(selector, "storage", 256).matches("[a-z0-9_.-]+:[a-z0-9_./-]+"), "Activation storage target is not a resource location");
                require(boundedText(selector, "key", 128).matches("[A-Za-z0-9_-]+"), "Activation storage key contains unsupported path syntax");
            }
            default -> throw invalid("Activation effect selector kind is unsupported");
        }
        id(selector, "resourceId"); return selector;
    }

    private static boolean resourceMember(JsonNode values, String resourceId) {
        return contains(values, resourceId);
    }
    private static boolean contains(JsonNode values, String expected) {
        if (values.isArray()) for (JsonNode value : values) if (value.isTextual() && expected.equals(value.textValue())) return true;
        return false;
    }
    private static boolean sameJson(JsonNode left, JsonNode right) {
        return left != null && right != null && ContractJson.digest(left).equals(ContractJson.digest(right));
    }
    private static ArrayNode array(ObjectNode object, String field, int min, int max) {
        if (!(object.get(field) instanceof ArrayNode values) || values.size() < min || values.size() > max) throw invalid("Activation array exceeds its capacity");
        return values;
    }
    private static long integer(JsonNode value, long min, long max) {
        if (value == null || !value.isNumber()) throw invalid("Activation integer is invalid");
        try {
            BigInteger number = value.decimalValue().toBigIntegerExact();
            if (number.compareTo(BigInteger.valueOf(min)) < 0 || number.compareTo(BigInteger.valueOf(max)) > 0) throw invalid("Activation integer exceeds its range");
            return number.longValueExact();
        } catch (ArithmeticException exception) { throw invalid("Activation integer is invalid"); }
    }
    private static void exact(ObjectNode value, Set<String> fields) {
        if (value.size() != fields.size()) throw invalid("Activation object has missing or extra fields");
        value.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid("Activation object has an unknown field"); });
    }
    private static String text(ObjectNode value, String field) {
        if (!value.path(field).isTextual()) throw invalid("Activation field must be text"); return value.path(field).textValue();
    }
    private static String boundedText(ObjectNode value, String field, int max) {
        String text = text(value, field);
        require(!text.isEmpty() && text.length() <= max && text.indexOf('\u0000') < 0, "Activation text exceeds its capacity"); return text;
    }
    private static String id(ObjectNode value, String field) {
        String text = text(value, field); require(text.matches(ID), "Activation identifier is invalid"); return text;
    }
    private static String sha(ObjectNode value, String field) {
        String text = text(value, field); require(text.matches(SHA), "Activation digest is invalid"); return text;
    }
    private static void require(boolean condition, String message) { if (!condition) throw invalid(message); }
    private static ContractException invalid(String message) { return new ContractException("NATIVE_ACTIVATION_INVALID", message); }
}
