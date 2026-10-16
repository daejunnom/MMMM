package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mojang.brigadier.ParseResults;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;

/**
 * Applies only the closed, Rust-sealed native command projection. No scene lowering,
 * NBT construction, object transforms, persistence, rollback or lifecycle chaining lives here.
 */
final class NativeSceneExecutor {
    private static final int MAX_APPROVAL_BYTES = 1024 * 1024;
    private static final int MAX_ITEMS = 256;
    private static final int MAX_LINE_BYTES = 16 * 1024;
    private static final int EFFECT_BATCH = 8;
    private static final Set<String> EXECUTION_FIELDS = Set.of("stepId", "argumentsDigest", "preparedChangeSha256",
            "format", "phase", "targetProfileId", "targetArtifactDigest", "compilerDigest", "codecDigest",
            "targetScope", "resourceTargets", "observedTargets", "steps", "nativeActivationProofs");
    private static final Set<String> STEP_FIELDS = Set.of("phase", "source_object_id", "source_node_id",
            "instance_id", "owner_prefab_id", "instruction", "encoded_commands", "commandDigest");
    private static final Set<String> DISPLAY_PROTECTED = Set.of("Tags", "transformation", "interpolation_duration",
            "start_interpolation", "teleport_duration", "Pos", "Passengers", "id", "UUID", "Rotation", "rotation");
    private final ContractJson contracts;

    NativeSceneExecutor(ContractJson contracts) { this.contracts = Objects.requireNonNull(contracts); }

    /** Closed action-output declaration, colocated with the actual native receipt producer. */
    static ObjectNode outputSchema() {
        ObjectNode dispatch = ContractJson.newObject();
        dispatch.set("index", integerSchema(0, MAX_ITEMS - 1, false));
        dispatch.set("beforeDigest", digestSchema(false)); dispatch.set("returnInt32", integerSchema(Integer.MIN_VALUE, Integer.MAX_VALUE, true));
        dispatch.set("afterDigest", digestSchema(true)); dispatch.set("failureCode", stringSchema("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"));
        ObjectNode receipt = ContractJson.newObject(); receipt.set("selector", selectorSchema()); receipt.set("rawSha256", digestSchema(false));
        receipt.set("status", enumSchema("known", "unknown", "unsupported")); receipt.set("presence", enumSchema("present", "absent", "unknown"));
        receipt.set("coverage", enumSchema("full_target", "tracked_changes_only", "best_effort"));
        receipt.set("membershipScope", stringSchema("^[a-z0-9_]{1,128}$")); receipt.set("captureScope", stringSchema("^[a-z0-9_]{1,128}$"));
        receipt.set("observedFromTick", stringSchema("^(0|[1-9][0-9]{0,9})$")); receipt.set("observedToTick", stringSchema("^(0|[1-9][0-9]{0,9})$"));
        ObjectNode properties = ContractJson.newObject(); properties.set("phase", enumSchema("stage", "activate", "cleanup"));
        properties.set("contextDigest", digestSchema(false)); properties.set("preparedChangeSha256", digestSchema(false));
        properties.set("completionClaim", enumSchema("independent_authority_readback_required"));
        properties.set("nativeCommandReturnInt32", arraySchema(integerSchema(Integer.MIN_VALUE, Integer.MAX_VALUE, false), 0, MAX_ITEMS));
        properties.set("nativeDispatchReceipts", arraySchema(objectSchema(dispatch, "index", "beforeDigest", "returnInt32", "afterDigest"), 0, MAX_ITEMS));
        properties.set("nativeTargetReceipts", arraySchema(objectSchema(receipt, "selector", "rawSha256", "status", "presence", "coverage", "membershipScope", "captureScope", "observedFromTick", "observedToTick"), 1, MAX_ITEMS));
        properties.set("indirectEffects", enumSchema("not_observed", "none_dispatched"));
        return objectSchema(properties, "phase", "contextDigest", "preparedChangeSha256", "completionClaim", "nativeCommandReturnInt32",
                "nativeDispatchReceipts", "nativeTargetReceipts", "indirectEffects");
    }

    private static ObjectNode selectorSchema() {
        ObjectNode schema = ContractJson.newObject(); ArrayNode variants = schema.putArray("oneOf");
        for (String kind : List.of("block_state", "block_entity", "entity", "storage", "score", "objective")) {
            ObjectNode properties = ContractJson.newObject(); properties.set("kind", enumSchema(kind));
            switch (kind) {
                case "block_state", "block_entity" -> {
                    properties.set("dimension", stringSchema("^[a-z0-9_.-]+:[a-z0-9_./-]+$"));
                    properties.set("position", arraySchema(integerSchema(Integer.MIN_VALUE, Integer.MAX_VALUE, false), 3, 3));
                    variants.add(objectSchema(properties, "kind", "dimension", "position"));
                }
                case "entity" -> {
                    properties.set("dimension", stringSchema("^[a-z0-9_.-]+:[a-z0-9_./-]+$"));
                    properties.set("uuid", stringSchema("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"));
                    properties.set("expectedType", stringSchema("^[a-z0-9_.-]+:[a-z0-9_./-]+$")); variants.add(objectSchema(properties, "kind", "dimension", "uuid", "expectedType"));
                }
                case "storage" -> {
                    properties.set("storage", stringSchema("^[a-z0-9_.-]+:[a-z0-9_./-]+$")); properties.set("key", stringSchema("^[A-Za-z0-9_-]{1,128}$"));
                    properties.set("resourceId", stringSchema("^[a-z0-9][a-z0-9._:-]{0,127}$")); variants.add(objectSchema(properties, "kind", "storage", "key", "resourceId"));
                }
                case "score" -> {
                    properties.set("objective", stringSchema("^[A-Za-z0-9_.#-]{1,128}$")); properties.set("holder", stringSchema("^[A-Za-z0-9_.#-]{1,128}$"));
                    properties.set("resourceId", stringSchema("^[a-z0-9][a-z0-9._:-]{0,127}$")); variants.add(objectSchema(properties, "kind", "objective", "holder", "resourceId"));
                }
                case "objective" -> {
                    properties.set("objective", stringSchema("^[A-Za-z0-9_.#-]{1,128}$")); properties.set("resourceId", stringSchema("^[a-z0-9][a-z0-9._:-]{0,127}$"));
                    variants.add(objectSchema(properties, "kind", "objective", "resourceId"));
                }
                default -> throw new AssertionError();
            }
        }
        return schema;
    }
    private static ObjectNode objectSchema(ObjectNode properties, String... required) {
        ObjectNode schema = ContractJson.newObject().put("type", "object").put("additionalProperties", false); schema.set("properties", properties);
        ArrayNode names = schema.putArray("required"); for (String name : required) names.add(name); return schema;
    }
    private static ObjectNode arraySchema(JsonNode items, int minimum, int maximum) {
        ObjectNode schema = ContractJson.newObject().put("type", "array").put("minItems", minimum).put("maxItems", maximum); schema.set("items", items); return schema;
    }
    private static ObjectNode enumSchema(String... values) {
        ObjectNode schema = ContractJson.newObject().put("type", "string"); ArrayNode enumeration = schema.putArray("enum"); for (String value : values) enumeration.add(value); return schema;
    }
    private static ObjectNode stringSchema(String pattern) { return ContractJson.newObject().put("type", "string").put("pattern", pattern); }
    private static ObjectNode digestSchema(boolean nullable) {
        ObjectNode schema = ContractJson.newObject().put("pattern", "^[a-f0-9]{64}$");
        if (nullable) schema.putArray("type").add("string").add("null"); else schema.put("type", "string"); return schema;
    }
    private static ObjectNode integerSchema(int minimum, int maximum, boolean nullable) {
        ObjectNode schema = ContractJson.newObject().put("minimum", minimum).put("maximum", maximum);
        if (nullable) schema.putArray("type").add("integer").add("null"); else schema.put("type", "integer"); return schema;
    }

    /**
     * The parent binds these methods to the actual installed authority, lifecycle indices,
     * immutable compiler/codec pins and native command execution facility. There are no
     * permissive defaults. A matching digest never substitutes for these live guards.
     */
    interface NativeInspector {
        NativeTargets.Observation inspect(ObjectNode exactSelector);
        void requireInstruction(ObjectNode installedContext, ObjectNode approvedExecution,
                                ObjectNode sealedStep, List<ObjectNode> exactApprovedTargets, boolean dispatchBoundary);
        void requireCommand(ObjectNode installedContext, ObjectNode approvedExecution, ObjectNode sealedStep,
                            int commandIndex, ParseResults<CommandSourceStack> parsed, List<ObjectNode> exactApprovedTargets, boolean dispatchBoundary);
        /** Uses the admitted Minecraft execution context and limits; never replaces a global result consumer. */
        int dispatch(ParseResults<CommandSourceStack> parsed) throws CommandSyntaxException;
    }

    ProviderResult execute(MinecraftServer server, ServerPlayer pairedPlayer, ObjectNode installedContext,
                           Invocation invocation, LocalContext local, ObjectNode approvedExecution,
                           NativeInspector inspector) {
        Objects.requireNonNull(server); Objects.requireNonNull(pairedPlayer); Objects.requireNonNull(invocation);
        Objects.requireNonNull(local); Objects.requireNonNull(inspector);
        requireCurrent(server, pairedPlayer, installedContext, invocation, local);
        if (ContractJson.bytes(approvedExecution).length > MAX_APPROVAL_BYTES) throw limit();
        ObjectNode context = installedContext.deepCopy(); ObjectNode approval = approvedExecution.deepCopy();
        exact(approval, EXECUTION_FIELDS); validateExecution(approval, context, invocation);
        List<ObjectNode> targets = targetRecords(approval);
        List<ObjectNode> steps = stepRecords(approval);
        ServerLevel level = level(server, text(context, "dimension"));
        CommandSourceStack source = NativeCommands.source(pairedPlayer, level, context);

        Map<String, NativeTargets.Observation> current = new LinkedHashMap<>();
        Set<String> used = new HashSet<>();
        List<PreparedCommand> commands = new ArrayList<>();
        for (int stepIndex = 0; stepIndex < steps.size(); stepIndex++) {
            requireCurrent(server, pairedPlayer, context, invocation, local);
            ObjectNode step = steps.get(stepIndex);
            List<ObjectNode> selected = instructionTargets(step, targets, approval);
            for (ObjectNode target : selected) used.add(selectorId(object(target, "selector")));
            inspector.requireInstruction(context.deepCopy(), approval.deepCopy(), step.deepCopy(), copies(selected), false);
            JsonNode encoded = step.get("encoded_commands");
            for (int commandIndex = 0; commandIndex < encoded.size(); commandIndex++) {
                local.checkActive();
                if (commands.size() >= MAX_ITEMS) throw limit();
                String command = encoded.get(commandIndex).textValue();
                requireOperationSignature(step, commandIndex, command);
                ParseResults<CommandSourceStack> parsed = server.getCommands().getDispatcher().parse(new StringReader(command), source);
                requireCompleteParse(parsed);
                inspector.requireCommand(context.deepCopy(), approval.deepCopy(), step.deepCopy(), commandIndex, parsed, copies(selected), false);
                commands.add(new PreparedCommand(stepIndex, commandIndex, step, selected, parsed));
            }
        }
        if (used.size() != targets.size()) throw failure("NATIVE_FOOTPRINT_MISMATCH", "Every sealed before target must belong to the selected instructions");
        preflightEffectBudget(commands.size(), invocation, approval);
        // Read-only preparation completes before entering the first mutation boundary.
        for (ObjectNode target : targets) {
            requireCurrent(server, pairedPlayer, context, invocation, local);
            NativeTargets.Observation observed = inspect(inspector, object(target, "selector"));
            if (!text(target, "expectedDigest").equals(observed.sha256())
                    || !text(target, "expectedPresence").equals(observed.raw().path("presence").asText())) {
                throw failure("PRECONDITION_CHANGED", "Actual native before state differs from its sealed observation");
            }
            current.put(selectorId(object(target, "selector")), observed);
        }
        for (ObjectNode target : targets) requireBefore(current.get(selectorId(object(target, "selector"))), target, steps, current, targets);

        ObjectNode data = ContractJson.newObject().put("phase", text(approval, "phase"))
                .put("contextDigest", invocation.contextDigest()).put("preparedChangeSha256", text(approval, "preparedChangeSha256"))
                .put("completionClaim", "independent_authority_readback_required");
        ArrayNode returned = data.putArray("nativeCommandReturnInt32");
        ArrayNode receipts = data.putArray("nativeDispatchReceipts");
        ArrayNode pending = ContractJson.newObject().putArray("commands");
        boolean started = false; boolean unknown = false; String failed = null;
        try {
            for (int index = 0; index < commands.size(); index++) {
                PreparedCommand command = commands.get(index);
                requireCurrent(server, pairedPlayer, context, invocation, local);
                for (ObjectNode target : command.targets()) {
                    ObjectNode selector = object(target, "selector"); String id = selectorId(selector);
                    NativeTargets.Observation fresh = inspect(inspector, selector);
                    if (!current.get(id).sha256().equals(fresh.sha256())) {
                        throw failure("TARGET_DRIFT", "A native target changed between guarded dispatches");
                    }
                    current.put(id, fresh);
                }
                for (ObjectNode target : command.targets()) requireBefore(current.get(selectorId(object(target, "selector"))), target, List.of(command.step()), current, command.targets());
                inspector.requireInstruction(context.deepCopy(), approval.deepCopy(), command.step().deepCopy(), copies(command.targets()), true);
                inspector.requireCommand(context.deepCopy(), approval.deepCopy(), command.step().deepCopy(),
                        command.commandIndex(), command.parsed(), copies(command.targets()), true);
                String beforeDigest = observationsDigest(current, command.targets());
                if (!started) { local.beginMutation(); started = true; }
                ObjectNode receipt = ContractJson.newObject().put("index", index).put("beforeDigest", beforeDigest);
                try {
                    // The parser and the native dispatcher receive the identical Rust source, including Unicode and escapes.
                    int value = inspector.dispatch(command.parsed());
                    returned.add(value); receipt.put("returnInt32", value);
                } catch (CommandSyntaxException exception) {
                    receipt.putNull("returnInt32").put("failureCode", "NATIVE_COMMAND_FAILED");
                    unknown = true; failed = "NATIVE_COMMAND_FAILED";
                } catch (RuntimeException exception) {
                    receipt.putNull("returnInt32").put("failureCode", exception instanceof ContractException contract ? contract.code() : "NATIVE_DISPATCH_FAILED");
                    unknown = true; failed = receipt.path("failureCode").asText();
                }
                boolean afterKnown = true;
                try {
                    for (ObjectNode target : command.targets()) {
                        ObjectNode selector = object(target, "selector");
                        NativeTargets.Observation after = inspect(inspector, selector);
                        current.put(selectorId(selector), after);
                    }
                    for (ObjectNode target : command.targets()) afterKnown &= fullyCovered(current.get(selectorId(object(target, "selector"))), target, current, command.targets());
                    receipt.put("afterDigest", observationsDigest(current, command.targets()));
                } catch (RuntimeException exception) {
                    receipt.putNull("afterDigest"); afterKnown = false;
                    if (failed == null) failed = exception instanceof ContractException contract ? contract.code() : "NATIVE_READBACK_FAILED";
                }
                // Direct target receipts never prove command-triggered, neighbor or scheduled effects elsewhere.
                unknown |= !afterKnown || indirectEffectsPossible(command.step());
                receipts.add(receipt.deepCopy()); pending.add(receipt.deepCopy());
                if (pending.size() == EFFECT_BATCH || failed != null) flush(local, pending, invocation, approval);
                if (failed != null) break;
                if (receipt.path("returnInt32").intValue() <= 0) {
                    // A zero/fork count is preserved, not turned into an effect count or a completion proof.
                    failed = "NATIVE_RETURN_UNCONFIRMED"; break;
                }
            }
        } catch (RuntimeException exception) {
            failed = exception instanceof ContractException contract ? contract.code() : "NATIVE_EXECUTION_FAILED";
            if (started) unknown = true;
        }
        if (started && !pending.isEmpty()) {
            try { flush(local, pending, invocation, approval); }
            catch (RuntimeException exception) { unknown = true; failed = "NATIVE_EFFECT_RECORD_FAILED"; }
        }
        var observed = data.putArray("nativeTargetReceipts");
        for (ObjectNode target : targets) {
            ObjectNode selector = object(target, "selector"); NativeTargets.Observation actual = current.get(selectorId(selector));
            ObjectNode raw = actual.raw();
            ObjectNode receipt = ContractJson.newObject().put("rawSha256", actual.sha256()).put("status", raw.path("status").asText())
                    .put("presence", raw.path("presence").asText()).put("coverage", raw.path("coverage").asText())
                    .put("membershipScope", raw.path("membershipScope").asText()).put("captureScope", raw.path("captureScope").asText())
                    .put("observedFromTick", Long.toString(actual.fromTick())).put("observedToTick", Long.toString(actual.toTick()));
            receipt.set("selector", selector.deepCopy()); observed.add(receipt);
        }
        data.put("indirectEffects", started ? "not_observed" : "none_dispatched");
        String effects = !started ? "none" : unknown ? "unknown" : "recorded";
        if (failed == null) return ProviderResult.complete(contracts, data, effects);
        ObjectNode result = ProviderResult.failed(contracts, failed, effects).wire(); result.set("data", data);
        return new ProviderResult(contracts, result);
    }

    private void validateExecution(ObjectNode approval, ObjectNode context, Invocation invocation) {
        if (!"mmmm.native-scene-command/1".equals(text(approval, "format"))) throw invalid();
        id(text(approval, "stepId")); id(text(approval, "targetProfileId"));
        for (String field : Set.of("argumentsDigest", "preparedChangeSha256", "targetArtifactDigest", "compilerDigest", "codecDigest")) digest(text(approval, field));
        if (!invocation.stepId().equals(text(approval, "stepId")) || !invocation.argumentsDigest().equals(text(approval, "argumentsDigest"))) {
            throw failure("INVOCATION_APPROVAL_MISMATCH", "Sealed execution belongs to another immutable invocation");
        }
        phase(text(approval, "phase"));
        ObjectNode scope = object(approval, "targetScope"); contracts.validate("Scope", scope);
        requireScopeSubset(scope, object(context, "scope"));
        array(approval, "steps", true); array(approval, "observedTargets", true); array(approval, "resourceTargets", false);
        array(approval, "nativeActivationProofs", false);
    }

    private static List<ObjectNode> stepRecords(ObjectNode approval) {
        List<ObjectNode> result = new ArrayList<>(); int count = 0;
        for (JsonNode value : approval.get("steps")) {
            ObjectNode step = ContractJson.object(value).deepCopy(); exact(step, STEP_FIELDS);
            if (!text(approval, "phase").equals(text(step, "phase"))) throw invalid();
            for (String field : Set.of("source_object_id", "instance_id", "owner_prefab_id")) id(text(step, field));
            if (!step.path("source_node_id").isNull()) id(text(step, "source_node_id"));
            ObjectNode instruction = object(step, "instruction"); validateInstruction(instruction, text(step, "phase"));
            ArrayNode commands = array(step, "encoded_commands", true);
            int expected = instruction.path("kind").asText().startsWith("state_") && "scoreboard".equals(instruction.path("storage_kind").asText()) ? 2 : 1;
            if (commands.size() != expected) throw invalid();
            if ((count += commands.size()) > MAX_ITEMS) throw limit();
            for (JsonNode command : commands) {
                if (!command.isTextual()) throw invalid(); String source = command.textValue();
                if (source.isEmpty() || source.startsWith("/") || source.indexOf('\n') >= 0 || source.indexOf('\r') >= 0 || source.indexOf('\0') >= 0
                        || source.getBytes(StandardCharsets.UTF_8).length > MAX_LINE_BYTES) throw invalid();
            }
            digest(text(step, "commandDigest"));
            if (!text(step, "commandDigest").equals(ContractJson.digest(commands))) throw failure("NATIVE_COMMAND_DIGEST_MISMATCH", "Sealed ordered command source changed");
            result.add(step);
        }
        return List.copyOf(result);
    }

    private static void validateInstruction(ObjectNode value, String phase) {
        String kind = text(value, "kind");
        Set<String> fields = switch (kind) {
            case "display" -> Set.of("kind", "dimension", "tag", "entity_kind", "uuid", "position", "matrix", "payload");
            case "display_pose" -> Set.of("kind", "dimension", "tag", "entity_kind", "uuid", "matrix");
            case "block" -> Set.of("kind", "dimension", "position", "state");
            case "command_shell" -> Set.of("kind", "dimension", "position", "command_kind", "facing", "conditional");
            case "command_data" -> Set.of("kind", "dimension", "position", "source");
            case "command_activation" -> Set.of("kind", "dimension", "position", "auto");
            case "state_initialize" -> Set.of("kind", "storage", "key", "value", "storage_kind", "state_type", "lifecycle", "objective", "holder");
            case "state_remove" -> Set.of("kind", "storage", "key", "storage_kind", "objective", "holder");
            case "display_remove" -> Set.of("kind", "dimension", "uuid", "entity_kind");
            default -> throw invalid();
        };
        exact(value, fields);
        Set<String> permitted = switch (phase) {
            case "stage" -> Set.of("display", "block", "command_shell", "command_data", "state_initialize");
            case "activate" -> Set.of("command_activation", "display_pose");
            case "cleanup" -> Set.of("command_activation", "state_remove", "display_remove");
            default -> throw invalid();
        };
        if (!permitted.contains(kind)) throw failure("NATIVE_PHASE_MISMATCH", "Instruction is outside the selected lifecycle phase");
        if (value.has("dimension")) location(text(value, "dimension"));
        if (value.has("uuid")) uuid(value.get("uuid"));
        if (value.has("entity_kind")) enumText(value, "entity_kind", Set.of("block", "item", "text"));
        if (value.has("position")) {
            if ("display".equals(kind)) finiteArray(value.get("position"), 3, false);
            else NativeBlocks.position(value.get("position"));
        }
        switch (kind) {
            case "display" -> {
                token(text(value, "tag")); finiteArray(value.get("matrix"), 16, true);
                ObjectNode payload = object(value, "payload");
                payload.fieldNames().forEachRemaining(key -> { if (DISPLAY_PROTECTED.contains(key)) throw invalid(); });
                if (payload.has("billboard") && (!payload.get("billboard").isTextual() || !"fixed".equals(payload.get("billboard").textValue()))) throw invalid();
            }
            case "display_pose" -> {
                token(text(value, "tag")); finiteArray(value.get("matrix"), 16, true);
                for (JsonNode octet : value.path("uuid")) if (!octet.isIntegralNumber()) throw invalid();
            }
            case "block" -> {
                ObjectNode state = object(value, "state"); exact(state, Set.of("blockId", "properties")); location(text(state, "blockId"));
                ObjectNode properties = object(state, "properties");
                properties.fields().forEachRemaining(entry -> { token(entry.getKey()); if (!entry.getValue().isTextual()) throw invalid(); token(entry.getValue().textValue()); });
            }
            case "command_shell" -> {
                enumText(value, "command_kind", Set.of("impulse", "chain", "repeating"));
                enumText(value, "facing", Set.of("north", "south", "west", "east", "up", "down")); bool(value, "conditional");
            }
            case "command_data" -> { if (text(value, "source").getBytes(StandardCharsets.UTF_8).length > MAX_LINE_BYTES) throw limit(); }
            case "command_activation" -> { bool(value, "auto"); if ("cleanup".equals(phase) && value.get("auto").booleanValue()) throw invalid(); }
            case "state_initialize", "state_remove" -> {
                location(text(value, "storage")); key(text(value, "key")); token(text(value, "objective")); token(text(value, "holder"));
                enumText(value, "storage_kind", Set.of("scoreboard", "storage_nbt"));
                if ("state_initialize".equals(kind)) {
                    enumText(value, "state_type", Set.of("int32", "float32", "boolean"));
                    enumText(value, "lifecycle", Set.of("load_once", "spawn"));
                    JsonNode scalar = value.get("value");
                    switch (text(value, "state_type")) {
                        case "boolean" -> { if (!scalar.isBoolean()) throw invalid(); }
                        case "int32" -> int32(scalar);
                        case "float32" -> nativeFloat(scalar);
                        default -> throw invalid();
                    }
                    if ("scoreboard".equals(text(value, "storage_kind")) && "float32".equals(text(value, "state_type"))) throw invalid();
                }
            }
            default -> { }
        }
    }

    private static List<ObjectNode> targetRecords(ObjectNode approval) {
        List<ObjectNode> result = new ArrayList<>(); Set<String> seen = new HashSet<>();
        for (JsonNode node : approval.get("observedTargets")) {
            ObjectNode target = ContractJson.object(node).deepCopy(); exact(target, Set.of("selector", "expectedDigest", "expectedPresence", "ownerTag"));
            ObjectNode selector = object(target, "selector"); validateSelector(selector);
            digest(text(target, "expectedDigest")); enumText(target, "expectedPresence", Set.of("present", "absent", "unknown"));
            if (!target.get("ownerTag").isNull()) { if (!"entity".equals(text(selector, "kind"))) throw invalid(); token(text(target, "ownerTag")); }
            if (!seen.add(selectorId(selector))) throw invalid(); result.add(target);
        }
        Set<String> mappings = new HashSet<>();
        for (JsonNode node : approval.get("resourceTargets")) {
            ObjectNode mapping = ContractJson.object(node); exact(mapping, Set.of("resourceId", "selector")); id(text(mapping, "resourceId"));
            ObjectNode selector = object(mapping, "selector"); validateSelector(selector);
            if (selector.has("resourceId") && !text(mapping, "resourceId").equals(text(selector, "resourceId"))) throw invalid();
            if (!seen.contains(selectorId(selector)) || !mappings.add(selectorId(selector))) throw invalid();
            requireResource(approval, text(mapping, "resourceId"));
        }
        for (ObjectNode record : result) {
            ObjectNode selector = object(record, "selector");
            if (selector.has("resourceId") && !mappings.contains(selectorId(selector))) throw failure("NATIVE_RESOURCE_MAPPING_MISSING", "Native state access requires an exact sealed resource mapping");
        }
        return List.copyOf(result);
    }

    private static List<ObjectNode> instructionTargets(ObjectNode step, List<ObjectNode> targets, ObjectNode approval) {
        ObjectNode instruction = object(step, "instruction"); String kind = text(instruction, "kind");
        List<ObjectNode> selected = new ArrayList<>(); Set<String> found = new HashSet<>();
        for (ObjectNode target : targets) {
            ObjectNode selector = object(target, "selector"); String type = text(selector, "kind"); boolean match = false;
            switch (kind) {
                case "display", "display_pose", "display_remove" -> match = "entity".equals(type)
                        && text(instruction, "dimension").equals(selector.path("dimension").asText())
                        && uuid(instruction.get("uuid")).toString().equals(selector.path("uuid").asText())
                        && ("minecraft:" + text(instruction, "entity_kind") + "_display").equals(selector.path("expectedType").asText());
                case "block", "command_shell", "command_data", "command_activation" -> match = Set.of("block_state", "block_entity").contains(type)
                        && text(instruction, "dimension").equals(selector.path("dimension").asText()) && NativeBlocks.position(instruction.get("position")).equals(NativeBlocks.position(selector.get("position")));
                case "state_initialize", "state_remove" -> {
                    if ("scoreboard".equals(text(instruction, "storage_kind"))) {
                        match = "objective".equals(type) && text(instruction, "objective").equals(selector.path("objective").asText())
                                || "score".equals(type) && text(instruction, "objective").equals(selector.path("objective").asText()) && text(instruction, "holder").equals(selector.path("holder").asText());
                    } else match = "storage".equals(type) && text(instruction, "storage").equals(selector.path("storage").asText()) && text(instruction, "key").equals(selector.path("key").asText());
                }
                default -> throw invalid();
            }
            if (match) {
                selected.add(target); found.add(type);
                if (Set.of("display", "display_pose").contains(kind) && (!target.get("ownerTag").isTextual() || !text(instruction, "tag").equals(text(target, "ownerTag")))) throw invalid();
                if ("display_remove".equals(kind) && !target.get("ownerTag").isTextual()) throw failure("OWNERSHIP_UNPROVEN", "Entity removal requires its sealed actual ownership tag");
            }
        }
        Set<String> required = switch (kind) {
            case "display", "display_pose", "display_remove" -> Set.of("entity");
            case "block", "command_shell", "command_data", "command_activation" -> Set.of("block_state", "block_entity");
            default -> "scoreboard".equals(text(instruction, "storage_kind")) ? Set.of("score", "objective") : Set.of("storage");
        };
        if (!found.equals(required) || selected.size() != required.size()) throw failure("NATIVE_FOOTPRINT_MISMATCH", "Instruction requires its exact complete typed before footprint");
        if ("command_activation".equals(kind) && instruction.path("auto").booleanValue()) {
            for (ObjectNode selector : activationEffects(approval, step)) {
                ObjectNode exact = null;
                for (ObjectNode target : targets) {
                    if (ContractJson.digest(selector).equals(ContractJson.digest(target.path("selector")))) {
                        if (exact != null) throw invalid();
                        exact = target;
                    }
                }
                if (exact == null || selected.stream().anyMatch(target -> selectorId(object(target, "selector")).equals(selectorId(selector)))) {
                    throw failure("NATIVE_FOOTPRINT_MISMATCH", "The sealed command effect target lacks its exact independent before footprint");
                }
                selected.add(exact);
            }
        }
        return List.copyOf(selected);
    }

    /** Selects private authority footprint only; source/producer/current-state admission is separate. */
    static List<ObjectNode> activationEffects(ObjectNode execution, ObjectNode step) {
        ObjectNode original = step.deepCopy(); original.remove("commandDigest");
        String nativeDigest = ContractJson.digest(original); ObjectNode proof = null;
        if (!execution.path("nativeActivationProofs").isArray()) throw invalid();
        for (JsonNode candidate : execution.path("nativeActivationProofs")) {
            if (nativeDigest.equals(candidate.path("nativeStepDigest").asText())) {
                if (proof != null) throw invalid(); proof = ContractJson.object(candidate);
            }
        }
        if (proof == null || !text(step, "commandDigest").equals(proof.path("commandDigest").asText())) {
            throw failure("NATIVE_COMMAND_SOURCE_UNAPPROVED", "Native activation has no exact retained source-effect authority");
        }
        if (!proof.path("effectSelectors").isArray() || proof.path("effectSelectors").size() > MAX_ITEMS) throw invalid();
        List<ObjectNode> effects = new ArrayList<>(); Set<String> unique = new HashSet<>();
        for (JsonNode effect : proof.path("effectSelectors")) {
            ObjectNode record = ContractJson.object(effect); exact(record, Set.of("selector", "access", "resource"));
            ObjectNode selector = object(record, "selector"); validateSelector(selector);
            if (!Set.of("score", "storage").contains(text(selector, "kind")) || !unique.add(selectorId(selector))) throw invalid();
            effects.add(selector.deepCopy());
        }
        return List.copyOf(effects);
    }

    private static void requireBefore(NativeTargets.Observation observation, ObjectNode target, List<ObjectNode> steps,
                                      Map<String, NativeTargets.Observation> observations, List<ObjectNode> targets) {
        ObjectNode raw = observation.raw(); ObjectNode selector = object(target, "selector");
        if (fullyCovered(observation, target, observations, targets)) {
            if ("entity".equals(text(selector, "kind"))) {
                if (!"present".equals(raw.path("presence").asText())) throw failure("OWNERSHIP_UNPROVEN", "Owned entity mutation requires a present actual entity");
                if (!target.get("ownerTag").isTextual()) throw failure("OWNERSHIP_UNPROVEN", "Owned entity target has no sealed ownership tag");
                boolean found = false;
                for (JsonNode tag : raw.path("payload").path("tags")) found |= tag.isTextual() && text(target, "ownerTag").equals(tag.textValue());
                if (!found) throw failure("OWNERSHIP_UNPROVEN", "Actual native entity lacks its sealed ownership tag");
            }
            return;
        }
        // This admits only a scoped spawn attempt. The mandatory instruction guard checks the loaded
        // exact spawn location and new owned UUID/tag. It does not assert persistent UUID absence.
        if ("entity".equals(text(selector, "kind")) && "unknown".equals(text(target, "expectedPresence"))
                && "unknown".equals(raw.path("status").asText()) && "unknown".equals(raw.path("presence").asText())
                && "loaded_uuid_not_observed".equals(raw.path("reason").asText())) {
            for (ObjectNode step : steps) {
                ObjectNode instruction = object(step, "instruction");
                if ("display".equals(text(instruction, "kind")) && uuid(instruction.get("uuid")).toString().equals(selector.path("uuid").asText())
                        && text(instruction, "dimension").equals(selector.path("dimension").asText()) && target.get("ownerTag").isTextual()
                        && text(instruction, "tag").equals(text(target, "ownerTag"))) return;
            }
        }
        throw failure("NATIVE_BEFORE_INCOMPLETE", "Native before footprint is not fully observed for this mutation");
    }

    private static boolean fullyCovered(NativeTargets.Observation observation, ObjectNode target,
                                        Map<String, NativeTargets.Observation> observations, List<ObjectNode> targets) {
        ObjectNode raw = observation.raw(); ObjectNode selector = object(target, "selector");
        if (fullKnown(raw)) return true;
        // A block state alone omits existing block-entity state. Only the exact corresponding
        // full native block-entity image completes this same-position aggregate footprint.
        if (!"block_state".equals(text(selector, "kind")) || !"known".equals(raw.path("status").asText())
                || !"present".equals(raw.path("presence").asText()) || !"tracked_changes_only".equals(raw.path("coverage").asText())
                || !"native_block_state".equals(raw.path("captureScope").asText()) || !raw.path("payload").path("hasBlockEntity").asBoolean(false)) return false;
        for (ObjectNode candidate : targets) {
            ObjectNode paired = object(candidate, "selector");
            if (!"block_entity".equals(text(paired, "kind")) || !selector.get("dimension").equals(paired.get("dimension"))
                    || !selector.get("position").equals(paired.get("position"))) continue;
            NativeTargets.Observation observed = observations.get(selectorId(paired));
            if (observed == null) return false; ObjectNode entity = observed.raw();
            return fullKnown(entity) && "present".equals(entity.path("presence").asText())
                    && raw.path("payload").path("blockState").equals(entity.path("payload").path("blockState"));
        }
        return false;
    }

    static void requireOperationSignature(ObjectNode step, int index, String command) {
        ObjectNode instruction = object(step, "instruction"); String kind = text(instruction, "kind"); String prefix;
        switch (kind) {
            case "display" -> {
                prefix = "execute in " + text(instruction, "dimension") + " run summon minecraft:" + text(instruction, "entity_kind") + "_display ";
                if (!command.startsWith(prefix)) throw invalid();
                String rest = command.substring(prefix.length()); String[] parts = rest.split(" ", 4);
                if (parts.length != 4 || !parts[3].startsWith("{") || !parts[3].endsWith("}")) throw invalid();
                for (int axis = 0; axis < 3; axis++) {
                    double actual;
                    try { actual = Double.parseDouble(parts[axis]); } catch (NumberFormatException exception) { throw invalid(); }
                    if (!parts[axis].matches("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?") || !Double.isFinite(actual)
                            || Double.doubleToRawLongBits(actual) != Double.doubleToRawLongBits(instruction.get("position").get(axis).doubleValue())) throw invalid();
                }
                // Native typed-NBT/UUID/tag/payload/matrix comparison is required in requireCommand.
            }
            case "display_pose" -> {
                if (index != 0) throw invalid();
                finiteArray(instruction.get("matrix"), 16, true);
                prefix = "execute in " + text(instruction, "dimension") + " as " + uuid(instruction.get("uuid"))
                        + " if entity @s[type=minecraft:" + text(instruction, "entity_kind") + "_display,tag="
                        + text(instruction, "tag") + "] run data merge entity @s {transformation:[";
                String suffix = "],interpolation_duration:0,start_interpolation:0,teleport_duration:0}";
                if (!command.startsWith(prefix) || !command.endsWith(suffix)) throw invalid();
                String[] matrix = command.substring(prefix.length(), command.length() - suffix.length()).split(",", -1);
                if (matrix.length != 16) throw invalid();
                for (int component = 0; component < matrix.length; component++) {
                    String literal = matrix[component];
                    if (!literal.matches("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?f")) throw invalid();
                    float actual;
                    try { actual = Float.parseFloat(literal.substring(0, literal.length() - 1)); }
                    catch (NumberFormatException exception) { throw invalid(); }
                    if (!Float.isFinite(actual) || Float.floatToRawIntBits(actual)
                            != Float.floatToRawIntBits(instruction.path("matrix").path(component).floatValue())) throw invalid();
                }
                // Native parsed NBT must independently contain only this matrix and the three zero resets.
            }
            case "block", "command_shell", "command_data", "command_activation" -> {
                String position = positionText(instruction.get("position"));
                prefix = "execute in " + text(instruction, "dimension") + " run ";
                if ("block".equals(kind)) {
                    String state = text(object(instruction, "state"), "blockId"); String tail = command.substring(Math.min(command.length(), (prefix + "setblock " + position + " ").length()));
                    if (!command.startsWith(prefix + "setblock " + position + " ") || !(tail.equals(state) || tail.startsWith(state + "[") && tail.endsWith("]"))) throw invalid();
                } else if ("command_shell".equals(kind)) {
                    String block = switch (text(instruction, "command_kind")) { case "impulse" -> "command_block"; case "chain" -> "chain_command_block"; default -> "repeating_command_block"; };
                    String expected = prefix + "setblock " + position + " minecraft:" + block + "[facing=" + text(instruction, "facing")
                            + ",conditional=" + instruction.get("conditional").booleanValue() + "]{Command:\"\",auto:0b,TrackOutput:0b}";
                    if (!command.equals(expected)) throw invalid();
                } else if ("command_data".equals(kind)) {
                    if (!command.startsWith(prefix + "data merge block " + position + " {Command:") || !command.endsWith(",auto:0b,TrackOutput:0b}")) throw invalid();
                } else if (!command.equals(prefix + "data merge block " + position + " {auto:" + (instruction.get("auto").booleanValue() ? "1" : "0") + "b}")) throw invalid();
            }
            case "display_remove" -> {
                String expected = "execute in " + text(instruction, "dimension") + " as " + uuid(instruction.get("uuid"))
                        + " if entity @s[type=minecraft:" + text(instruction, "entity_kind") + "_display] run kill @s";
                if (!command.equals(expected)) throw invalid();
            }
            case "state_initialize", "state_remove" -> {
                String objective = text(instruction, "objective"), holder = text(instruction, "holder");
                if ("scoreboard".equals(text(instruction, "storage_kind"))) {
                    if ("state_remove".equals(kind)) {
                        String expected = index == 0 ? "scoreboard players reset " + holder + " " + objective : "scoreboard objectives remove " + objective;
                        if (!command.equals(expected)) throw invalid();
                    } else if (index == 0) {
                        if (!command.equals("scoreboard objectives add " + objective + " dummy")) throw invalid();
                    } else {
                        prefix = "scoreboard players set " + holder + " " + objective + " ";
                        if ("load_once".equals(text(instruction, "lifecycle"))) prefix = "execute unless score " + holder + " " + objective + " matches -2147483648..2147483647 run " + prefix;
                        if (!command.startsWith(prefix) || !command.substring(prefix.length()).matches("-?(?:0|[1-9][0-9]*)")) throw invalid();
                    }
                } else {
                    String address = text(instruction, "storage") + " states." + text(instruction, "key");
                    if ("state_remove".equals(kind)) { if (!command.equals("data remove storage " + address)) throw invalid(); }
                    else {
                        prefix = "data modify storage " + address + " set value ";
                        if ("load_once".equals(text(instruction, "lifecycle"))) prefix = "execute unless data storage " + address + " run " + prefix;
                        if (!command.startsWith(prefix) || command.length() == prefix.length() || command.substring(prefix.length()).indexOf(' ') >= 0) throw invalid();
                    }
                }
            }
            default -> throw invalid();
        }
    }

    private static void requireCompleteParse(ParseResults<CommandSourceStack> parsed) {
        if (parsed.getReader().canRead() || !parsed.getExceptions().isEmpty()) throw failure("NATIVE_COMMAND_SYNTAX_INVALID", "Native parser did not consume the entire sealed command");
        var context = parsed.getContext(); int depth = 0;
        while (context.getChild() != null) { if (++depth > 32) throw limit(); context = context.getChild(); }
        if (context.getCommand() == null) throw failure("NATIVE_COMMAND_SYNTAX_INVALID", "Sealed command has no complete native executable context");
    }

    private static void requireCurrent(MinecraftServer server, ServerPlayer player, ObjectNode context, Invocation invocation, LocalContext local) {
        local.requireGameThread(); local.checkActive(); local.requirePermission("mmmm:command_execute");
        if (!server.isSameThread()) throw failure("WRONG_THREAD", "Native scene execution requires the server thread");
        if (server.getPlayerList().getPlayer(player.getUUID()) != player || player.isRemoved()) throw failure("EXECUTOR_DISCONNECTED", "The actual paired player is no longer present");
        if (!context.equals(local.executionContext()) || !context.equals(invocation.context())) throw failure("CONTEXT_CHANGED", "Execution requires the original installed authority context");
        ObjectNode environment = object(context, "environment");
        if (!"game".equals(environment.path("kind").asText()) || !"server".equals(environment.path("side").asText()) || !environment.path("worldId").isTextual()) throw invalid();
    }

    private static NativeTargets.Observation inspect(NativeInspector inspector, ObjectNode selector) {
        NativeTargets.Observation observed = Objects.requireNonNull(inspector.inspect(selector.deepCopy()));
        ObjectNode raw = observed.raw();
        if (!"mmmm.native.target/1".equals(raw.path("format").asText()) || !selector.equals(raw.get("selector"))
                || !observed.sha256().equals(ContractJson.sha256(observed.bytes())) || !observed.sha256().equals(ContractJson.digest(raw))) {
            throw failure("NATIVE_OBSERVATION_INVALID", "Independent observation does not bind the exact native selector and bytes");
        }
        return observed;
    }
    private static String observationsDigest(Map<String, NativeTargets.Observation> values, List<ObjectNode> targets) {
        ArrayNode receipts = ContractJson.newObject().putArray("targets");
        for (ObjectNode target : targets) {
            String selector = selectorId(object(target, "selector")); NativeTargets.Observation actual = values.get(selector);
            receipts.add(ContractJson.newObject().put("selectorDigest", selector).put("rawSha256", actual.sha256()));
        }
        return ContractJson.digest(receipts);
    }
    private static void flush(LocalContext local, ArrayNode pending, Invocation invocation, ObjectNode approval) {
        local.recordEffect(effectReceipt(pending, invocation, approval)); pending.removeAll();
    }
    private static ObjectNode effectReceipt(ArrayNode pending, Invocation invocation, ObjectNode approval) {
        ObjectNode effect = ContractJson.newObject().put("kind", "native_scene_dispatch").put("stepId", invocation.stepId())
                .put("phase", text(approval, "phase")).put("preparedChangeSha256", text(approval, "preparedChangeSha256"))
                .put("receiptScope", "direct_native_target_digests_and_dispatch_returns").put("indirectEffects", "not_observed");
        effect.set("commands", pending.deepCopy()); return effect;
    }
    private static void preflightEffectBudget(int commands, Invocation invocation, ObjectNode approval) {
        ArrayNode batch = ContractJson.newObject().putArray("commands"); int bytes = 0;
        for (int index = 0; index < commands; index++) {
            ObjectNode receipt = ContractJson.newObject().put("index", index).put("beforeDigest", "f".repeat(64))
                    .put("returnInt32", Integer.MIN_VALUE).put("afterDigest", "f".repeat(64));
            // At most one failed dispatch is admitted: execution stops immediately afterward.
            if (index == commands - 1) receipt.put("failureCode", "F".repeat(128)); batch.add(receipt);
            if (batch.size() == EFFECT_BATCH || index == commands - 1) {
                int current = ContractJson.bytes(effectReceipt(batch, invocation, approval)).length;
                if (current > 16 * 1024 || bytes > 64 * 1024 - current) throw limit(); bytes += current; batch.removeAll();
            }
        }
    }
    private static boolean fullKnown(ObjectNode raw) {
        return "known".equals(raw.path("status").asText()) && Set.of("present", "absent").contains(raw.path("presence").asText())
                && "full_target".equals(raw.path("coverage").asText());
    }
    private static boolean indirectEffectsPossible(ObjectNode step) {
        return Set.of("block", "command_shell", "command_data", "command_activation", "display", "display_pose", "display_remove").contains(object(step, "instruction").path("kind").asText());
    }
    private static void requireScopeSubset(ObjectNode scope, ObjectNode installed) {
        if (!text(scope, "projectId").equals(text(installed, "projectId"))) throw failure("SCOPE_DENIED", "Native execution belongs to another installed project");
        for (String field : Set.of("resourceIds", "objectIds", "externalTargetIds")) {
            if (scope.path(field).size() > MAX_ITEMS) throw limit();
            for (JsonNode requested : scope.path(field)) {
                boolean contained = false; for (JsonNode admitted : installed.path(field)) contained |= requested.equals(admitted);
                if (!contained) throw failure("SCOPE_DENIED", "Native execution exceeds the installed explicit scope");
            }
        }
        if (scope.path("regions").size() > MAX_ITEMS) throw limit();
        for (JsonNode region : scope.path("regions")) {
            boolean contained = false;
            for (JsonNode admitted : installed.path("regions")) {
                if (!region.path("dimension").equals(admitted.path("dimension")) || !region.path("contextId").equals(admitted.path("contextId")) || !region.path("worldId").equals(admitted.path("worldId"))) continue;
                boolean inside = true;
                for (int axis = 0; axis < 3; axis++) inside &= region.path("min").get(axis).bigIntegerValue().compareTo(region.path("maxExclusive").get(axis).bigIntegerValue()) < 0
                        && admitted.path("min").get(axis).bigIntegerValue().compareTo(region.path("min").get(axis).bigIntegerValue()) <= 0
                        && region.path("maxExclusive").get(axis).bigIntegerValue().compareTo(admitted.path("maxExclusive").get(axis).bigIntegerValue()) <= 0;
                contained |= inside;
            }
            if (!contained) throw failure("SCOPE_DENIED", "Native region exceeds the installed world/context scope");
        }
    }
    private static void requireResource(ObjectNode approval, String resourceId) {
        for (JsonNode admitted : approval.path("targetScope").path("resourceIds")) if (admitted.isTextual() && resourceId.equals(admitted.textValue())) return;
        throw failure("SCOPE_DENIED", "Native resource mapping exceeds the original approved scope");
    }
    private static void validateSelector(ObjectNode selector) {
        String kind = text(selector, "kind"); exact(selector, switch (kind) {
            case "block_state", "block_entity" -> Set.of("kind", "dimension", "position");
            case "entity" -> Set.of("kind", "dimension", "uuid", "expectedType");
            case "storage" -> Set.of("kind", "storage", "key", "resourceId");
            case "score" -> Set.of("kind", "objective", "holder", "resourceId");
            case "objective" -> Set.of("kind", "objective", "resourceId");
            default -> throw invalid();
        });
        if (selector.has("dimension")) location(text(selector, "dimension"));
        if (selector.has("position")) NativeBlocks.position(selector.get("position"));
        if (selector.has("uuid")) { UUID parsed; try { parsed = UUID.fromString(text(selector, "uuid")); } catch (IllegalArgumentException exception) { throw invalid(); } if (!parsed.toString().equals(text(selector, "uuid"))) throw invalid(); }
        if (selector.has("expectedType")) location(text(selector, "expectedType"));
        if (selector.has("storage")) location(text(selector, "storage"));
        if (selector.has("key")) key(text(selector, "key"));
        for (String field : Set.of("objective", "holder")) if (selector.has(field)) token(text(selector, field));
        if (selector.has("resourceId")) id(text(selector, "resourceId"));
    }
    private static ServerLevel level(MinecraftServer server, String dimension) {
        int count = 0;
        for (ServerLevel candidate : server.getAllLevels()) { if (++count > MAX_ITEMS) throw limit(); if (candidate.dimension().identifier().toString().equals(dimension)) return candidate; }
        throw failure("DIMENSION_UNKNOWN", "Approved native dimension is not currently loaded");
    }
    private static String positionText(JsonNode position) {
        var actual = NativeBlocks.position(position); return actual.getX() + " " + actual.getY() + " " + actual.getZ();
    }
    private static UUID uuid(JsonNode value) {
        if (!value.isArray() || value.size() != 16) throw invalid(); byte[] bytes = new byte[16];
        for (int index = 0; index < bytes.length; index++) { int current = int32(value.get(index)); if (current < 0 || current > 255) throw invalid(); bytes[index] = (byte) current; }
        ByteBuffer buffer = ByteBuffer.wrap(bytes); return new UUID(buffer.getLong(), buffer.getLong());
    }
    private static int int32(JsonNode value) {
        try { if (!value.isNumber()) throw new ArithmeticException(); return value.decimalValue().intValueExact(); }
        catch (ArithmeticException exception) { throw invalid(); }
    }
    private static void nativeFloat(JsonNode value) {
        if (!value.isNumber() || !Double.isFinite(value.doubleValue()) || !Float.isFinite(value.floatValue())
                || Double.doubleToRawLongBits(value.doubleValue()) != Double.doubleToRawLongBits((double) value.floatValue())) throw invalid();
    }
    private static void finiteArray(JsonNode value, int size, boolean nativeFloat) {
        if (!value.isArray() || value.size() != size) throw invalid();
        for (JsonNode component : value) {
            if (!component.isNumber() || !Double.isFinite(component.doubleValue())) throw invalid();
            if (nativeFloat) nativeFloat(component); else if (Math.abs(component.doubleValue()) > 30_000_000.0) throw invalid();
        }
    }
    private static ArrayNode array(ObjectNode value, String field, boolean nonempty) {
        if (!(value.get(field) instanceof ArrayNode result) || result.size() > MAX_ITEMS || nonempty && result.isEmpty()) throw invalid(); return result;
    }
    private static List<ObjectNode> copies(List<ObjectNode> values) {
        List<ObjectNode> result = new ArrayList<>(values.size()); for (ObjectNode value : values) result.add(value.deepCopy()); return List.copyOf(result);
    }
    private static String selectorId(ObjectNode selector) { return ContractJson.digest(selector); }
    private static ObjectNode object(ObjectNode value, String field) { return ContractJson.object(value.get(field)); }
    private static String text(ObjectNode value, String field) { if (!value.path(field).isTextual()) throw invalid(); return value.get(field).textValue(); }
    private static void bool(ObjectNode value, String field) { if (!value.path(field).isBoolean()) throw invalid(); }
    private static void enumText(ObjectNode value, String field, Set<String> values) { if (!values.contains(text(value, field))) throw invalid(); }
    private static void id(String value) { if (!value.matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid(); }
    private static void token(String value) { if (!value.matches("[A-Za-z0-9_.#-]{1,128}")) throw invalid(); }
    private static void key(String value) { if (!value.matches("[A-Za-z0-9_-]{1,128}")) throw failure("NATIVE_PATH_UNSUPPORTED", "The admitted state key must be a literal native key"); }
    private static void location(String value) { if (value.length() > 256 || !value.matches("[a-z0-9_.-]+:[a-z0-9_./-]+")) throw invalid(); }
    private static void digest(String value) { if (!value.matches("[a-f0-9]{64}")) throw invalid(); }
    private static void phase(String value) { if (!Set.of("stage", "activate", "cleanup").contains(value)) throw invalid(); }
    private static void exact(ObjectNode value, Set<String> fields) {
        if (value.size() != fields.size()) throw invalid(); value.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); });
    }
    private static ContractException invalid() { return failure("NATIVE_EXECUTION_INVALID", "Native execution is not the closed approved Rust projection"); }
    private static ContractException limit() { return failure("NATIVE_EXECUTION_LIMIT", "Native execution exceeds its finite budget"); }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
    private record PreparedCommand(int stepIndex, int commandIndex, ObjectNode step, List<ObjectNode> targets, ParseResults<CommandSourceStack> parsed) { }
}
