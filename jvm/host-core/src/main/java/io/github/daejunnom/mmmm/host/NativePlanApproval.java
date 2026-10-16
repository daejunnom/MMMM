package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Immutable private authority received over the approved anonymous bridge.
 * This is neither an original wire DTO nor a caller-supplied plan or permission grant.
 * The Rust authority owns plan, resource, compiler and codec validation; this class binds
 * its exact frozen projection to installed contexts and one operation before callbacks run.
 * A platform executor must additionally preflight the entire batch's typed instruction
 * footprints and exact commands before effects, then check live native state at dispatch.
 */
public final class NativePlanApproval {
    public static final int MAX_BYTES = 1024 * 1024;
    public static final int MAX_STEPS = 256;
    private static final int MAX_COMMAND_BYTES = 16_384;
    private static final String ID = "[a-z0-9][a-z0-9._:-]{0,127}";
    private static final String LOCATION = "[a-z0-9_.-]+:[a-z0-9_./-]+";
    private static final Set<String> MANIFEST_FIELDS = Set.of("kind", "protocolVersion", "principalId", "projectId",
            "planId", "planHash", "policyRevision", "contextPins", "expiresAt", "steps", "nativeExecutions");
    private static final Set<String> STEP_FIELDS = Set.of("stepId", "bindingId", "actionId", "actionDigest",
            "implementationDigest", "argumentsDigest", "contextId", "contextDigest", "resourcesRead", "resourcesWritten", "preconditions");
    private static final Set<String> EXECUTION_FIELDS = Set.of("stepId", "argumentsDigest", "preparedChangeSha256",
            "format", "phase", "targetProfileId", "targetArtifactDigest", "compilerDigest", "codecDigest", "targetScope",
            "resourceTargets", "observedTargets", "steps", "nativeActivationProofs");
    private static final Set<String> NATIVE_STEP_FIELDS = Set.of("phase", "source_object_id", "source_node_id",
            "instance_id", "owner_prefab_id", "instruction", "encoded_commands", "commandDigest");
    private final ContractJson contracts;
    private final Clock clock;
    private final ObjectNode manifest;
    private final Instant expiresAt;
    private final Map<String, ObjectNode> pins = new HashMap<>();
    private final Map<String, ObjectNode> steps = new HashMap<>();
    private final Map<String, ObjectNode> executions = new HashMap<>();
    private final Map<String, List<NativeActivationApproval>> activationProofs = new HashMap<>();
    private final NativeInvocationReservations reservations;
    private HostSession approvedSession;

    public NativePlanApproval(ContractJson contracts, JsonNode value) { this(contracts, value, Clock.systemUTC()); }

    public NativePlanApproval(ContractJson contracts, byte[] bytes, Clock clock) {
        this(contracts, parseBounded(bytes), clock);
    }

    public NativePlanApproval(ContractJson contracts, JsonNode value, Clock clock) {
        this.contracts = Objects.requireNonNull(contracts);
        this.clock = Objects.requireNonNull(clock);
        byte[] snapshot = ContractJson.bytes(value);
        if (snapshot.length > MAX_BYTES) throw invalid("Approval exceeds its byte limit");
        manifest = ContractJson.object(ContractJson.parse(snapshot)); exact(manifest, MANIFEST_FIELDS);
        equal(manifest, "kind", "native_plan_approval"); equal(manifest, "protocolVersion", ContractJson.VERSION);
        for (String field : Set.of("principalId", "projectId", "planId")) id(manifest, field);
        for (String field : Set.of("planHash", "policyRevision")) sha(manifest, field);
        try { expiresAt = Instant.parse(text(manifest, "expiresAt")); }
        catch (DateTimeParseException exception) { throw invalid("Approval expiry is not an instant"); }
        reservations = new NativeInvocationReservations(expiresAt, clock);
        for (JsonNode valuePin : array(manifest, "contextPins", 1, MAX_STEPS)) {
            contracts.validate("ContextPin", valuePin); ObjectNode pin = ContractJson.object(valuePin).deepCopy();
            if (!"game".equals(pin.path("environment").path("kind").asText())) throw invalid("Native approval needs a game context");
            putUnique(pins, text(pin, "contextId"), pin, "Context pin is duplicated");
        }
        for (JsonNode valueStep : array(manifest, "steps", 1, MAX_STEPS)) {
            ObjectNode step = ContractJson.object(valueStep).deepCopy(); exact(step, STEP_FIELDS);
            for (String field : Set.of("stepId", "bindingId", "contextId")) id(step, field);
            location(step, "actionId");
            for (String field : Set.of("actionDigest", "implementationDigest", "argumentsDigest", "contextDigest")) sha(step, field);
            ObjectNode pin = pins.get(text(step, "contextId"));
            if (pin == null || !text(pin, "contextDigest").equals(text(step, "contextDigest"))) throw invalid("Step context is not pinned");
            ids(step, "resourcesRead"); ids(step, "resourcesWritten");
            Set<String> conditions = new HashSet<>();
            for (JsonNode condition : array(step, "preconditions", 0, MAX_STEPS)) {
                contracts.validate("Precondition", condition);
                if (!conditions.add(condition.path("kind").asText() + "\u0000" + condition.path("subject").asText())) {
                    throw invalid("Precondition subject is duplicated");
                }
            }
            putUnique(steps, text(step, "stepId"), step, "Plan step is duplicated");
        }
        int nativeStepCount = 0;
        for (JsonNode valueExecution : array(manifest, "nativeExecutions", 0, MAX_STEPS)) {
            ObjectNode execution = ContractJson.object(valueExecution).deepCopy(); exact(execution, EXECUTION_FIELDS);
            id(execution, "stepId"); id(execution, "targetProfileId");
            equal(execution, "format", "mmmm.native-scene-command/1"); phase(execution);
            for (String field : Set.of("argumentsDigest", "preparedChangeSha256", "targetArtifactDigest", "compilerDigest", "codecDigest")) sha(execution, field);
            ObjectNode step = steps.get(text(execution, "stepId"));
            if (step == null || !text(step, "argumentsDigest").equals(text(execution, "argumentsDigest"))) throw invalid("Native execution is not bound to a plan step");
            contracts.validate("Scope", execution.path("targetScope"));
            ObjectNode targetScope = ContractJson.object(execution.path("targetScope"));
            if (!projectId().equals(text(targetScope, "projectId"))) throw invalid("Native target scope differs from approval project");
            validateRegions(targetScope);
            Map<String, ObjectNode> observed = new HashMap<>();
            for (JsonNode valueTarget : array(execution, "observedTargets", 1, MAX_STEPS)) {
                ObjectNode target = ContractJson.object(valueTarget); exact(target, Set.of("selector", "expectedDigest", "expectedPresence", "ownerTag"));
                ObjectNode selector = selector(target.path("selector")); sha(target, "expectedDigest");
                if (!Set.of("present", "absent", "unknown").contains(text(target, "expectedPresence"))) throw invalid("Expected target presence is unsupported");
                if (!target.path("ownerTag").isNull()) {
                    boundedText(target, "ownerTag", 256);
                    if (!"entity".equals(text(selector, "kind"))) throw invalid("Only entities may carry an ownership tag");
                }
                validateSelectorScope(selector, targetScope, pinFor(step), step);
                putUnique(observed, ContractJson.digest(selector), target.deepCopy(), "Observed selector is duplicated");
            }
            Map<String, String> selectorResources = new HashMap<>();
            Set<String> associations = new HashSet<>();
            for (JsonNode valueTarget : array(execution, "resourceTargets", 0, MAX_STEPS)) {
                ObjectNode target = ContractJson.object(valueTarget); exact(target, Set.of("resourceId", "selector"));
                String resourceId = id(target, "resourceId"); ObjectNode selector = selector(target.path("selector"));
                String selectorDigest = ContractJson.digest(selector);
                if (!observed.containsKey(selectorDigest)) throw invalid("Resource selector lacks an exact observed footprint");
                if (!contains(targetScope.path("resourceIds"), resourceId)
                        || (!contains(step.path("resourcesRead"), resourceId) && !contains(step.path("resourcesWritten"), resourceId))) {
                    throw invalid("Resource target is outside the frozen step resource scope");
                }
                if (selector.has("resourceId") && !resourceId.equals(text(selector, "resourceId"))) throw invalid("Selector resource differs from its association");
                if (!associations.add(resourceId + "\u0000" + selectorDigest)) throw invalid("Resource association is duplicated");
                String previous = selectorResources.putIfAbsent(selectorDigest, resourceId);
                if (previous != null && !previous.equals(resourceId)) throw invalid("Selector is associated with conflicting resources");
            }
            for (ObjectNode observedTarget : observed.values()) {
                ObjectNode selector = ContractJson.object(observedTarget.path("selector"));
                if (selector.has("resourceId") && !selectorResources.containsKey(ContractJson.digest(selector))) {
                    throw invalid("Resource selector has no trusted exact association");
                }
            }
            int commandCount = 0;
            for (JsonNode valueNativeStep : array(execution, "steps", 1, MAX_STEPS)) {
                if (++nativeStepCount > MAX_STEPS) throw invalid("Native instruction capacity is exhausted");
                ObjectNode nativeStep = ContractJson.object(valueNativeStep); validateSealedNativeStep(nativeStep);
                equal(nativeStep, "phase", text(execution, "phase"));
                ArrayNode commands = array(nativeStep, "encoded_commands", 1, 4);
                commandCount += commands.size(); if (commandCount > MAX_STEPS) throw invalid("Native command capacity is exhausted");
            }
            validatePresence(execution, observed);
            List<NativeActivationApproval> proofs = new java.util.ArrayList<>(); Set<String> proofSteps = new HashSet<>();
            for (JsonNode valueProof : array(execution, "nativeActivationProofs", 0, MAX_STEPS)) {
                NativeActivationApproval proof = new NativeActivationApproval(contracts, ContractJson.object(valueProof));
                proof.validateBindings(manifest, step, execution);
                if (!proofSteps.add(proof.snapshot().path("nativeStepDigest").asText())) throw invalid("Activation proof native step is duplicated");
                proofs.add(proof);
            }
            Set<String> activationSteps = new HashSet<>();
            for (JsonNode valueNativeStep : execution.path("steps")) {
                ObjectNode nativeStep = ContractJson.object(valueNativeStep);
                if ("activate".equals(text(nativeStep, "phase"))
                        && "command_activation".equals(nativeStep.path("instruction").path("kind").asText())
                        && nativeStep.path("instruction").path("auto").booleanValue()) {
                    if (!activationSteps.add(NativeActivationApproval.originalNativeStepDigest(nativeStep))) throw invalid("Activation instruction is duplicated");
                    int matches = 0; for (NativeActivationApproval proof : proofs) if (proof.matches(nativeStep)) matches++;
                    if (matches != 1) throw invalid("Each activation instruction requires its unique sealed authority proof");
                }
            }
            if (!activationSteps.equals(proofSteps)) throw invalid("Activation authority proof is unused by the selected execution");
            activationProofs.put(text(execution, "stepId"), List.copyOf(proofs));
            putUnique(executions, text(execution, "stepId"), execution, "Native execution step is duplicated");
        }
    }

    public String principalId() { return text(manifest, "principalId"); }
    public String projectId() { return text(manifest, "projectId"); }
    public String planId() { return text(manifest, "planId"); }
    public String planHash() { return text(manifest, "planHash"); }
    public String policyRevision() { return text(manifest, "policyRevision"); }
    public Instant expiresAt() { return expiresAt; }
    public ObjectNode manifest() { return manifest.deepCopy(); }

    /** Installer validation; an authority envelope cannot broaden an existing immutable context. */
    public synchronized void checkSession(HostSession session) {
        session.checkOpen(); requireSessionIdentity(session);
        if (!principalId().equals(session.principalRef())) throw mismatch();
        for (String contextId : pins.keySet()) validateContext(session.context(contextId));
        for (ObjectNode step : steps.values()) validateStepScope(session.context(text(step, "contextId")), step);
        for (ObjectNode execution : executions.values()) {
            ObjectNode step = steps.get(text(execution, "stepId"));
            requireScopeSubset(ContractJson.object(execution.path("targetScope")), session.context(text(step, "contextId")));
        }
        if (approvedSession == null && !clock.instant().isBefore(expiresAt)) throw expired();
        approvedSession = session;
    }

    /**
     * Admission is atomic and sticky even if the provider subsequently fails or is cancelled.
     * Only a previously admitted exact non-write control/history check may outlive expiry.
     * Live target policy/permissions remain the platform authority's separate responsibility.
     */
    public synchronized void checkInvocation(HostSession session, Invocation invocation, boolean write) {
        session.checkOpen(); requireSessionIdentity(session); ObjectNode context = session.context(invocation.contextId());
        validateContext(context);
        if (!principalId().equals(session.principalRef()) || !context.equals(invocation.context())) throw mismatch();
        ObjectNode step = requireStep(invocation);
        ObjectNode execution = executions.get(invocation.stepId());
        if (execution != null) {
            requireScopeSubset(ContractJson.object(execution.path("targetScope")), context);
            preparedChange(invocation, execution);
        }
        NativeInvocationReservations.Candidate candidate = reservations.inspect(invocation, write);
        validateStepScope(context, step);
        if (reservations.admit(candidate)) {
            approvedSession = session;
        }
    }

    /** No CAS access or domain lowering: return only the immutable authority projection. */
    public synchronized ObjectNode execution(Invocation invocation) {
        if (approvedSession == null) throw mismatch(); approvedSession.checkOpen();
        requireStep(invocation);
        if (!reservations.containsExact(invocation)) throw mismatch();
        ObjectNode execution = executions.get(invocation.stepId());
        if (execution == null) throw new ContractException("NATIVE_EXECUTION_UNAPPROVED", "This approved step has no native execution");
        preparedChange(invocation, execution); return execution.deepCopy();
    }

    /**
     * Return immutable evidence for one already admitted invocation and actual native source body.
     * A platform must still verify the current registered producer/profile/source receipt,
     * native generation, command-chain fence and target readback before mutation.
     */
    public synchronized ObjectNode activationProof(Invocation invocation, ObjectNode fullSealedStep, String rawSource) {
        ObjectNode execution = execution(invocation); ObjectNode nativeStep = fullSealedStep.deepCopy(); validateSealedNativeStep(nativeStep);
        ObjectNode context = approvedSession.context(invocation.contextId()); validateContext(context);
        if (!context.equals(invocation.context())) throw mismatch();
        if (!"activate".equals(text(nativeStep, "phase"))
                || !"command_activation".equals(nativeStep.path("instruction").path("kind").asText())
                || !nativeStep.path("instruction").path("auto").booleanValue()) throw invalid("A source proof is selected only when an activation instruction enables its command body");
        if (rawSource == null) throw invalid("Actual command source is required");
        ContractJson.bytes(ContractJson.newObject().put("source", rawSource));
        NativeActivationApproval selected = null;
        for (NativeActivationApproval proof : activationProofs.getOrDefault(invocation.stepId(), List.of())) {
            if (!proof.matches(nativeStep)) continue;
            if (selected != null) throw invalid("Activation proof selection is ambiguous"); selected = proof;
        }
        if (selected == null) throw new ContractException("NATIVE_ACTIVATION_UNAPPROVED", "The exact activation instruction has no admitted source proof");
        selected.validateBindings(manifest, requireStep(invocation), execution, context);
        selected.validateSourceBytes(rawSource.getBytes(StandardCharsets.UTF_8)); return selected.snapshot();
    }

    /** Pure source-frame validation; this method creates no plan membership or permission. */
    public static void validateSealedNativeStep(ObjectNode value) {
        byte[] snapshot = ContractJson.bytes(value); if (snapshot.length > MAX_BYTES) throw invalid("Sealed native step exceeds its byte limit");
        ObjectNode step = ContractJson.object(ContractJson.parse(snapshot)); exact(step, NATIVE_STEP_FIELDS); phase(step);
        for (String field : Set.of("source_object_id", "instance_id", "owner_prefab_id")) id(step, field);
        if (!step.path("source_node_id").isNull()) id(step, "source_node_id");
        ObjectNode instruction = ContractJson.object(step.path("instruction")); validateInstruction(instruction, text(step, "phase"));
        ArrayNode commands = array(step, "encoded_commands", 1, 4);
        int expectedCommands = instruction.path("kind").asText().startsWith("state_")
                && "scoreboard".equals(instruction.path("storage_kind").asText()) ? 2 : 1;
        if (commands.size() != expectedCommands) throw invalid("Sealed native command count differs from its instruction type");
        for (JsonNode command : commands) {
            if (!command.isTextual()) throw invalid("Native command must be exact text"); String raw = command.textValue();
            if (raw.isEmpty() || raw.startsWith("/") || raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\u0000') >= 0
                    || raw.getBytes(StandardCharsets.UTF_8).length > MAX_COMMAND_BYTES) throw invalid("Native command is not a bounded exact line");
        }
        if (!sha(step, "commandDigest").equals(ContractJson.digest(commands))) throw invalid("Native command digest changed");
    }

    /** Exact plan read footprint; native mutation callbacks must use the Invocation overload below. */
    public boolean resourceAllowed(ObjectNode installedContext, ObjectNode exactSelector) {
        return resourceAllowed(executions.values(), installedContext, exactSelector);
    }

    /** Restrict a native executor's inspector to its exact already admitted frozen step. */
    public synchronized boolean resourceAllowed(Invocation invocation, ObjectNode installedContext, ObjectNode exactSelector) {
        try {
            ObjectNode context = installedContext.deepCopy();
            if (!context.equals(invocation.context())) return false;
            return resourceAllowed(List.of(execution(invocation)), context, exactSelector);
        } catch (ContractException exception) { return false; }
    }

    private boolean resourceAllowed(Iterable<ObjectNode> allowedExecutions, ObjectNode installedContext, ObjectNode exactSelector) {
        try {
            ObjectNode context = installedContext.deepCopy(); ObjectNode selector = selector(exactSelector.deepCopy());
            validateContext(context);
            if (!selector.has("resourceId")) return false;
            String resourceId = text(selector, "resourceId");
            if (!contains(context.path("scope").path("resourceIds"), resourceId)) return false;
            for (ObjectNode execution : allowedExecutions) {
                ObjectNode step = steps.get(text(execution, "stepId"));
                if (!context.path("contextId").asText().equals(text(step, "contextId"))) continue;
                requireScopeSubset(ContractJson.object(execution.path("targetScope")), context);
                for (JsonNode association : execution.path("resourceTargets")) {
                    if (resourceId.equals(association.path("resourceId").asText()) && selector.equals(association.path("selector"))) return true;
                }
            }
            return false;
        } catch (ContractException exception) { return false; }
    }

    private void validateContext(ObjectNode context) {
        contracts.validate("ExecutionContext", context); ObjectNode pin = pins.get(context.path("contextId").asText());
        if (pin == null || !principalId().equals(context.path("principalRef").asText())
                || !projectId().equals(context.path("projectId").asText()) || !policyRevision().equals(context.path("policyRevision").asText())
                || !text(pin, "contextDigest").equals(context.path("contextDigest").asText())
                || !text(pin, "contextDigest").equals(ContractJson.contextDigest(context))
                || !pin.path("environment").equals(context.path("environment"))) throw mismatch();
    }

    private ObjectNode requireStep(Invocation invocation) {
        ObjectNode step = steps.get(invocation.stepId());
        if (step == null || !text(step, "bindingId").equals(invocation.bindingId()) || !text(step, "actionId").equals(invocation.actionId())
                || !text(step, "actionDigest").equals(invocation.actionDigest())
                || !text(step, "implementationDigest").equals(invocation.implementationDigest())
                || !text(step, "argumentsDigest").equals(invocation.argumentsDigest()) || !text(step, "contextId").equals(invocation.contextId())
                || !text(step, "contextDigest").equals(invocation.contextDigest())) throw mismatch();
        return step;
    }

    private void preparedChange(Invocation invocation, ObjectNode execution) {
        ObjectNode arguments = invocation.arguments(); exact(arguments, Set.of("preparedChange"));
        contracts.validate("ResourceRef", arguments.path("preparedChange"));
        if (!text(execution, "preparedChangeSha256").equals(arguments.path("preparedChange").path("sha256").asText())) throw mismatch();
    }

    private ObjectNode pinFor(ObjectNode step) { return pins.get(text(step, "contextId")); }

    private static void validateStepScope(ObjectNode context, ObjectNode step) {
        // Lists are private plan metadata; they are never claimed as fields of the original Invocation.
        for (String field : Set.of("resourcesRead", "resourcesWritten")) {
            for (JsonNode resourceId : step.path(field)) {
                if (!contains(context.path("scope").path("resourceIds"), resourceId.asText())) throw mismatch();
            }
        }
    }

    private void requireSessionIdentity(HostSession session) {
        if (approvedSession != null && approvedSession != session) {
            throw new ContractException("NATIVE_APPROVAL_SESSION_MISMATCH", "A frozen approval belongs to exactly one host session");
        }
    }

    private static void requireScopeSubset(ObjectNode target, ObjectNode context) {
        ObjectNode installed = ContractJson.object(context.path("scope"));
        if (!text(target, "projectId").equals(context.path("projectId").asText())
                || !text(target, "projectId").equals(text(installed, "projectId"))) throw mismatch();
        for (String field : Set.of("resourceIds", "objectIds", "externalTargetIds")) {
            for (JsonNode id : target.path(field)) if (!contains(installed.path(field), id.asText())) throw mismatch();
        }
        validateRegions(target); validateRegions(installed);
        for (JsonNode requested : target.path("regions")) {
            if (!context.path("contextId").asText().equals(requested.path("contextId").asText())
                    || !context.path("environment").path("worldId").asText().equals(requested.path("worldId").asText())
                    || (context.has("dimension") && !context.path("dimension").asText().equals(requested.path("dimension").asText()))) throw mismatch();
            boolean contained = false;
            for (JsonNode allowed : installed.path("regions")) {
                if (!requested.path("contextId").equals(allowed.path("contextId")) || !requested.path("worldId").equals(allowed.path("worldId"))
                        || !requested.path("dimension").equals(allowed.path("dimension"))) continue;
                boolean boxContained = true;
                for (int axis = 0; axis < 3; axis++) {
                    if (integer(requested.path("min").get(axis)) < integer(allowed.path("min").get(axis))
                            || integer(requested.path("maxExclusive").get(axis)) > integer(allowed.path("maxExclusive").get(axis))) boxContained = false;
                }
                if (boxContained) { contained = true; break; }
            }
            if (!contained) throw mismatch();
        }
    }

    private static void validateRegions(ObjectNode scope) {
        for (JsonNode region : array(scope, "regions", 0, MAX_STEPS)) {
            for (int axis = 0; axis < 3; axis++) {
                if (integer(region.path("min").get(axis)) >= integer(region.path("maxExclusive").get(axis))) throw invalid("Native region is empty or reversed");
            }
        }
    }

    private static void validateSelectorScope(ObjectNode selector, ObjectNode scope, ObjectNode pin, ObjectNode step) {
        if (selector.has("resourceId") && !contains(scope.path("resourceIds"), text(selector, "resourceId"))) throw invalid("Native resource selector exceeds target scope");
        if (!selector.has("dimension")) return;
        boolean found = false;
        for (JsonNode region : scope.path("regions")) {
            if (!text(step, "contextId").equals(region.path("contextId").asText())
                    || !pin.path("environment").path("worldId").asText().equals(region.path("worldId").asText())
                    || !text(selector, "dimension").equals(region.path("dimension").asText())) continue;
            boolean inside = true;
            if (selector.has("position")) for (int axis = 0; axis < 3; axis++) {
                int coordinate = integer(selector.path("position").get(axis));
                if (coordinate < integer(region.path("min").get(axis)) || coordinate >= integer(region.path("maxExclusive").get(axis))) inside = false;
            }
            if (inside) { found = true; break; }
        }
        if (!found) throw invalid("Native selector exceeds the exact contextual world region");
    }

    private static ObjectNode selector(JsonNode value) {
        ObjectNode selector = ContractJson.object(value); String kind = text(selector, "kind");
        Set<String> fields = switch (kind) {
            case "block_state", "block_entity" -> Set.of("kind", "dimension", "position");
            case "entity" -> Set.of("kind", "dimension", "uuid", "expectedType");
            case "storage" -> Set.of("kind", "storage", "key", "resourceId");
            case "score" -> Set.of("kind", "objective", "holder", "resourceId");
            case "objective" -> Set.of("kind", "objective", "resourceId");
            default -> throw invalid("Native selector kind is unsupported");
        };
        exact(selector, fields);
        for (String field : Set.of("dimension", "expectedType", "storage")) if (selector.has(field)) location(selector, field);
        if (selector.has("position")) integerVector(selector.path("position"), 3);
        if (selector.has("uuid")) {
            String valueUuid = text(selector, "uuid");
            try { if (!UUID.fromString(valueUuid).toString().equals(valueUuid)) throw invalid("Native UUID is not canonical"); }
            catch (IllegalArgumentException exception) { throw invalid("Native UUID is not canonical"); }
        }
        for (String field : Set.of("key", "objective", "holder")) if (selector.has(field)) {
            if (!boundedText(selector, field, 128).matches("[A-Za-z0-9_.#-]+")) throw invalid("Native literal target name is unsupported");
        }
        if (selector.has("key") && !text(selector, "key").matches("[A-Za-z0-9_-]+")) throw invalid("Native storage key cannot contain path syntax");
        if (selector.has("resourceId")) id(selector, "resourceId");
        return selector;
    }

    private static void validateInstruction(ObjectNode instruction, String phase) {
        String kind = text(instruction, "kind"); Set<String> fields = switch (kind) {
            case "display" -> Set.of("kind", "dimension", "tag", "entity_kind", "uuid", "position", "matrix", "payload");
            case "display_pose" -> Set.of("kind", "dimension", "tag", "entity_kind", "uuid", "matrix");
            case "block" -> Set.of("kind", "dimension", "position", "state");
            case "command_shell" -> Set.of("kind", "dimension", "position", "command_kind", "facing", "conditional");
            case "command_data" -> Set.of("kind", "dimension", "position", "source");
            case "command_activation" -> Set.of("kind", "dimension", "position", "auto");
            case "state_initialize" -> Set.of("kind", "storage", "key", "value", "storage_kind", "state_type", "lifecycle", "objective", "holder");
            case "state_remove" -> Set.of("kind", "storage", "key", "storage_kind", "objective", "holder");
            case "display_remove" -> Set.of("kind", "dimension", "uuid", "entity_kind");
            default -> throw invalid("Native instruction kind is unsupported");
        };
        exact(instruction, fields);
        // Match the current Rust compiler's stage, activation and cleanup vectors.
        // A valid phase alone grants no authority over an indirect command body.
        boolean phaseMatches = switch (phase) {
            case "stage" -> Set.of("display", "block", "command_shell", "command_data", "state_initialize").contains(kind);
            case "activate" -> Set.of("command_activation", "display_pose").contains(kind);
            case "cleanup" -> Set.of("state_remove", "display_remove").contains(kind)
                    || ("command_activation".equals(kind) && instruction.path("auto").isBoolean() && !instruction.path("auto").booleanValue());
            default -> false;
        };
        if (!phaseMatches) throw invalid("Native instruction differs from its selected phase");
        for (String field : Set.of("dimension", "storage")) if (instruction.has(field)) location(instruction, field);
        if (instruction.has("uuid")) {
            ArrayNode uuid = array(instruction, "uuid", 16, 16);
            for (JsonNode octet : uuid) { int number = integer(octet); if (number < 0 || number > 255) throw invalid("Native UUID octet is invalid"); }
        }
        if (instruction.has("entity_kind") && !Set.of("block", "item", "text").contains(text(instruction, "entity_kind"))) throw invalid("Native display type is unsupported");
        if ("display".equals(kind)) {
            boundedText(instruction, "tag", 256); finiteVector(instruction.path("position"), 3, false); finiteVector(instruction.path("matrix"), 16, true);
            ContractJson.object(instruction.path("payload"));
        } else if ("display_pose".equals(kind)) {
            if (!boundedText(instruction, "tag", 128).matches("[A-Za-z0-9_.#-]+")) throw invalid("Display pose ownership tag is not a literal native token");
            finiteVector(instruction.path("matrix"), 16, true);
        } else if (instruction.has("position")) integerVector(instruction.path("position"), 3);
        if ("block".equals(kind)) {
            ObjectNode state = ContractJson.object(instruction.path("state")); exact(state, Set.of("blockId", "properties")); location(state, "blockId");
            ObjectNode properties = ContractJson.object(state.path("properties"));
            if (properties.size() > MAX_STEPS) throw invalid("Native block property capacity is exhausted");
            properties.fields().forEachRemaining(entry -> { if (entry.getKey().isEmpty() || entry.getKey().length() > 128 || !entry.getValue().isTextual()
                    || entry.getValue().textValue().isEmpty() || entry.getValue().textValue().length() > 128) throw invalid("Native block property is invalid"); });
        }
        for (String field : Set.of("auto", "conditional")) if (instruction.has(field) && !instruction.path(field).isBoolean()) throw invalid("Native instruction flag is invalid");
        for (String field : Set.of("command_kind", "facing", "storage_kind", "state_type", "lifecycle", "objective", "holder", "key")) {
            if (instruction.has(field)) boundedText(instruction, field, 256);
        }
        if (instruction.has("source") && text(instruction, "source").getBytes(StandardCharsets.UTF_8).length > MAX_COMMAND_BYTES) throw invalid("Native command data source exceeds its line budget");
        if ("command_shell".equals(kind)) {
            enumeration(instruction, "command_kind", Set.of("impulse", "chain", "repeating"));
            enumeration(instruction, "facing", Set.of("north", "south", "east", "west", "up", "down"));
        }
        if (kind.startsWith("state_")) {
            enumeration(instruction, "storage_kind", Set.of("scoreboard", "storage_nbt"));
            for (String field : Set.of("key", "objective", "holder")) {
                if (!text(instruction, field).matches("[A-Za-z0-9_.#-]+")) throw invalid("Native state target token is unsupported");
            }
            if (!text(instruction, "key").matches("[A-Za-z0-9_-]+")) throw invalid("Native storage key cannot contain path syntax");
            if ("state_initialize".equals(kind)) {
                enumeration(instruction, "state_type", Set.of("int32", "float32", "boolean"));
                enumeration(instruction, "lifecycle", Set.of("load_once", "spawn"));
                JsonNode scalar = instruction.path("value");
                switch (text(instruction, "state_type")) {
                    case "int32" -> integer(scalar);
                    case "float32" -> { nativeFloat(scalar); if ("scoreboard".equals(text(instruction, "storage_kind"))) throw invalid("Scoreboard cannot store a Float32 state"); }
                    case "boolean" -> { if (!scalar.isBoolean()) throw invalid("Native boolean state has a non-boolean value"); }
                    default -> throw invalid("Native state scalar type is unsupported");
                }
            }
        }
    }

    private static void validatePresence(ObjectNode execution, Map<String, ObjectNode> observed) {
        Set<String> poses = new HashSet<>();
        for (ObjectNode target : observed.values()) {
            ObjectNode selector = ContractJson.object(target.path("selector")); boolean spawn = false; boolean remove = false;
            for (JsonNode step : execution.path("steps")) {
                ObjectNode instruction = ContractJson.object(step.path("instruction")); String kind = text(instruction, "kind");
                if (!Set.of("display", "display_pose", "display_remove").contains(kind) || !"entity".equals(text(selector, "kind"))) continue;
                if (!text(instruction, "dimension").equals(text(selector, "dimension"))
                        || !("minecraft:" + text(instruction, "entity_kind") + "_display").equals(text(selector, "expectedType"))
                        || !nativeUuid(instruction.path("uuid")).equals(text(selector, "uuid"))) continue;
                if ("display".equals(kind)) {
                    if (!target.path("ownerTag").isTextual() || !text(instruction, "tag").equals(text(target, "ownerTag"))) throw invalid("Spawn ownership tag differs from its sealed source");
                    spawn = true;
                } else if ("display_pose".equals(kind)) {
                    if (!"present".equals(text(target, "expectedPresence")) || !target.path("ownerTag").isTextual()
                            || !text(instruction, "tag").equals(text(target, "ownerTag"))) throw invalid("Display pose requires its exact present owned before target");
                    poses.add(ContractJson.digest(step));
                } else {
                    if (!target.path("ownerTag").isTextual() || !"present".equals(text(target, "expectedPresence"))) throw invalid("Destructive entity target needs present owned before state");
                    remove = true;
                }
            }
            if ("unknown".equals(text(target, "expectedPresence")) && (!spawn || remove)) throw invalid("Unknown before state is permitted only for a sealed scoped spawn attempt");
            if (spawn && "present".equals(text(target, "expectedPresence"))) throw invalid("A display spawn cannot overwrite an observed UUID");
        }
        for (JsonNode step : execution.path("steps")) {
            if ("display_pose".equals(step.path("instruction").path("kind").asText()) && !poses.contains(ContractJson.digest(step))) {
                throw invalid("Display pose lacks its exact UUID, type, dimension and owned before target");
            }
        }
    }
    private static String nativeUuid(JsonNode value) {
        if (!(value instanceof ArrayNode values) || values.size() != 16) throw invalid("Native UUID is invalid");
        long most = 0; long least = 0;
        for (int index = 0; index < 16; index++) {
            int octet = integer(values.get(index)); if (octet < 0 || octet > 255) throw invalid("Native UUID octet is invalid");
            if (index < 8) most = (most << 8) | octet; else least = (least << 8) | octet;
        }
        return new UUID(most, least).toString();
    }
    private static void finiteVector(JsonNode value, int count, boolean exactFloat32) {
        if (!(value instanceof ArrayNode values) || values.size() != count) throw invalid("Native float vector is invalid");
        for (JsonNode scalar : values) {
            if (!scalar.isNumber() || !Double.isFinite(scalar.doubleValue())) throw invalid("Native scalar is not finite");
            if (exactFloat32) nativeFloat(scalar);
        }
    }
    private static void nativeFloat(JsonNode scalar) {
        if (!scalar.isNumber() || !Double.isFinite(scalar.doubleValue()) || !Float.isFinite(scalar.floatValue())
                || scalar.doubleValue() != (double) scalar.floatValue()) throw invalid("Native scalar is not an exact widened Float32");
    }
    private static void integerVector(JsonNode value, int count) {
        if (!(value instanceof ArrayNode values) || values.size() != count) throw invalid("Native integer vector is invalid");
        values.forEach(NativePlanApproval::integer);
    }
    private static int integer(JsonNode value) {
        if (value == null || !value.isIntegralNumber() || value.bigIntegerValue().compareTo(BigInteger.valueOf(Integer.MIN_VALUE)) < 0
                || value.bigIntegerValue().compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) throw invalid("Native coordinate is outside signed 32-bit bounds");
        return value.intValue();
    }
    private static JsonNode parseBounded(byte[] bytes) {
        if (bytes.length > MAX_BYTES) throw invalid("Approval exceeds its byte limit"); return ContractJson.parse(bytes);
    }
    private static ArrayNode array(ObjectNode object, String field, int min, int max) {
        if (!(object.get(field) instanceof ArrayNode array) || array.size() < min || array.size() > max) throw invalid("Approval array is outside its capacity"); return array;
    }
    private static Set<String> ids(ObjectNode object, String field) {
        Set<String> values = new HashSet<>();
        for (JsonNode value : array(object, field, 0, MAX_STEPS)) {
            if (!value.isTextual() || !value.textValue().matches(ID) || !values.add(value.textValue())) throw invalid("Resource IDs are invalid or duplicated");
        }
        return values;
    }
    private static void exact(ObjectNode object, Set<String> fields) {
        if (object.size() != fields.size()) throw invalid("Approval object has missing or extra fields");
        object.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid("Approval object has an unknown field"); });
    }
    private static String text(ObjectNode object, String field) {
        if (!object.path(field).isTextual()) throw invalid("Approval field must be text"); return object.path(field).textValue();
    }
    private static String boundedText(ObjectNode object, String field, int max) {
        String value = text(object, field); if (value.isEmpty() || value.length() > max || value.indexOf('\u0000') >= 0) throw invalid("Approval text is outside its capacity"); return value;
    }
    private static String id(ObjectNode object, String field) { String value = text(object, field); if (!value.matches(ID)) throw invalid("Approval identifier is invalid"); return value; }
    private static String sha(ObjectNode object, String field) { String value = text(object, field); if (!value.matches("[a-f0-9]{64}")) throw invalid("Approval digest is invalid"); return value; }
    private static void location(ObjectNode object, String field) { if (!boundedText(object, field, 256).matches(LOCATION)) throw invalid("Native resource location is invalid"); }
    private static void equal(ObjectNode object, String field, String expected) { if (!expected.equals(text(object, field))) throw invalid("Approval discriminator or pin differs"); }
    private static void phase(ObjectNode object) { if (!Set.of("stage", "activate", "cleanup").contains(text(object, "phase"))) throw invalid("Native phase is unsupported"); }
    private static void enumeration(ObjectNode object, String field, Set<String> values) { if (!values.contains(text(object, field))) throw invalid("Native instruction enum is unsupported"); }
    private static boolean contains(JsonNode array, String value) { if (array.isArray()) for (JsonNode item : array) if (item.isTextual() && value.equals(item.textValue())) return true; return false; }
    private static void putUnique(Map<String, ObjectNode> map, String id, ObjectNode value, String message) { if (map.putIfAbsent(id, value) != null) throw invalid(message); }
    private static ContractException invalid(String message) { return new ContractException("NATIVE_APPROVAL_INVALID", message); }
    private static ContractException mismatch() { return new ContractException("NATIVE_APPROVAL_MISMATCH", "Invocation or installed scope differs from the exact frozen plan approval"); }
    private static ContractException rebound() { return new ContractException("NATIVE_APPROVAL_REBOUND", "A frozen approval cannot be rebound to another operation or invocation"); }
    private static ContractException expired() { return new ContractException("NATIVE_APPROVAL_EXPIRED", "The frozen plan approval has expired"); }
}
