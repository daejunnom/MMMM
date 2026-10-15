package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mojang.brigadier.ParseResults;
import com.mojang.brigadier.context.CommandContextBuilder;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import com.mojang.brigadier.tree.ArgumentCommandNode;
import com.mojang.brigadier.tree.CommandNode;
import com.mojang.brigadier.tree.LiteralCommandNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.arguments.blocks.BlockInput;
import net.minecraft.core.BlockPos;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.Tag;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.level.block.entity.BlockEntity;

/** Checks native identities and parsed values; it does not lower scenes or construct desired NBT. */
final class NativeExecutionGuard implements NativeSceneExecutor.NativeInspector {
    private static final int MAX_TARGETS = 256;
    private static final int MAX_COMMAND_NODES = 128;
    private static final int MAX_NBT_NODES = 16_384;
    private static final int MAX_NBT_DEPTH = 64;
    private static final int MAX_NBT_ENTRIES = 4096;
    private static final Set<String> DISPLAY_FIELDS = Set.of("Tags", "UUID", "billboard", "Rotation",
            "transformation", "start_interpolation", "interpolation_duration", "teleport_duration");
    private static final Set<String> NATIVE_COMMAND_OWNERS = Set.of("net.minecraft.server.commands.ExecuteCommand",
            "net.minecraft.server.commands.SetBlockCommand", "net.minecraft.server.commands.SummonCommand",
            "net.minecraft.server.commands.KillCommand", "net.minecraft.server.commands.ScoreboardCommand",
            "net.minecraft.server.commands.data.DataCommands");

    /** Rechecks the installed route and actual source/profile proof, rather than trusting the DTO pins. */
    @FunctionalInterface
    interface CurrentAdmission {
        void require(ObjectNode installedContext, ObjectNode approvedExecution);
    }

    /**
     * The platform owner must inspect actual command-block auto/powered/scheduled-tick state.
     * Activation additionally needs the retained Rust approval for the actual command source's effects.
     * An NBT digest or an administrator flag cannot implement this authority by itself.
     */
    @FunctionalInterface
    interface CommandBlockAuthority {
        void require(ServerLevel level, BlockPos position, BlockEntity actual, ObjectNode installedContext,
                     ObjectNode approvedExecution, ObjectNode sealedStep, boolean activation);
    }

    /** Executes using the admitted native execution facility and its bounded context. */
    @FunctionalInterface
    interface NativeDispatch {
        int execute(ParseResults<CommandSourceStack> parsed) throws CommandSyntaxException;
    }

    private final MinecraftServer server;
    private final ServerPlayer player;
    private final LoadedChunks chunks;
    private final LoadedEntities entities;
    private final ObjectNode context;
    private final ObjectNode execution;
    private final NativeTargets.ResourceAuthority resources;
    private final CurrentAdmission admission;
    private final CommandBlockAuthority commandBlocks;
    private final NativeDispatch dispatcher;
    private final Invocation invocation;
    private final NativeTombstones tombstones;
    private PendingDispatch pending;
    private OwnedRemoval removal;
    private OwnedPose pose;

    NativeExecutionGuard(ContractJson contracts, MinecraftServer server, ServerPlayer player, LoadedChunks chunks, LoadedEntities entities,
                         Invocation invocation, ObjectNode approvedExecution,
                         NativeTargets.ResourceAuthority resources, CurrentAdmission admission,
                         CommandBlockAuthority commandBlocks, NativeDispatch dispatcher, NativeTombstones tombstones) {
        Objects.requireNonNull(contracts);
        this.server = Objects.requireNonNull(server); this.player = Objects.requireNonNull(player);
        this.chunks = Objects.requireNonNull(chunks); this.entities = Objects.requireNonNull(entities);
        this.invocation = Objects.requireNonNull(invocation); this.context = invocation.context();
        this.execution = Objects.requireNonNull(approvedExecution).deepCopy();
        this.resources = Objects.requireNonNull(resources); this.admission = Objects.requireNonNull(admission);
        this.commandBlocks = Objects.requireNonNull(commandBlocks); this.dispatcher = Objects.requireNonNull(dispatcher);
        this.tombstones = Objects.requireNonNull(tombstones);
        contracts.validate("Scope", context.path("scope")); contracts.validate("Scope", execution.path("targetScope"));
        if (!invocation.stepId().equals(text(execution, "stepId"))
                || !invocation.argumentsDigest().equals(text(execution, "argumentsDigest"))) throw invalid();
    }

    @Override public NativeTargets.Observation inspect(ObjectNode exactSelector) {
        current(context, execution);
        return NativeTargets.observe(chunks, entities, level(), context, exactSelector.deepCopy(), resources,
                (actualLevel, actualContext, selector) -> tombstones.destroyed(invocation, actualLevel, actualContext, selector));
    }

    @Override public void requireInstruction(ObjectNode installedContext, ObjectNode approvedExecution,
                                             ObjectNode sealedStep, List<ObjectNode> exactApprovedTargets,
                                             boolean dispatchBoundary) {
        current(installedContext, approvedExecution);
        requireSealedStep(sealedStep);
        if (dispatchBoundary) { removal = null; pose = null; }
        ObjectNode instruction = object(sealedStep, "instruction");
        List<ObservedTarget> targets = targets(approvedExecution, exactApprovedTargets);
        String kind = text(instruction, "kind");
        if (instruction.has("dimension") && !text(instruction, "dimension").equals(text(context, "dimension"))) {
            throw fail("CONTEXT_SCOPE_MISMATCH", "The native instruction differs from the actual installed level");
        }
        switch (kind) {
            case "display" -> requireSpawn(instruction, targets);
            case "display_pose" -> requirePose(instruction, targets, dispatchBoundary);
            case "display_remove" -> requireRemoval(instruction, targets, dispatchBoundary);
            case "block" -> {
                BlockPos position = requirePosition(instruction);
                requirePair(targets, position);
                if (chunks.require(level(), position).getBlockState(position).hasBlockEntity()
                        || NativeBlocks.decode(instruction.get("state")).hasBlockEntity()) {
                    throw fail("NATIVE_BLOCK_ENTITY_UNSUPPORTED", "A state-only block instruction cannot replace or create a block entity");
                }
            }
            case "command_shell" -> {
                BlockPos position = requirePosition(instruction); requirePair(targets, position);
                var chunk = chunks.require(level(), position);
                BlockEntity actual = chunk.getBlockEntities().get(position);
                // Replacing a live native BE can execute its own removal semantics. A separate retained-target
                // instruction and complete effect approval are required rather than a generic shell overwrite.
                if (chunk.getBlockState(position).hasBlockEntity() || actual != null) {
                    throw fail("NATIVE_BLOCK_ENTITY_UNSUPPORTED", "Command shell staging cannot overwrite an existing block entity");
                }
                commandBlocks.require(level(), position, actual, context.deepCopy(), execution.deepCopy(),
                        sealedStep.deepCopy(), false);
            }
            case "command_data", "command_activation" -> {
                BlockPos position = requirePosition(instruction);
                if ("command_activation".equals(kind) && instruction.path("auto").booleanValue()) {
                    requireActivationTargets(approvedExecution, sealedStep, targets, position);
                } else requirePair(targets, position);
                BlockEntity actual = chunks.require(level(), position).getBlockEntities().get(position);
                if (actual == null && !dispatchBoundary && "command_data".equals(kind)
                        && hasEarlierShell(approvedExecution, sealedStep, instruction)) return;
                actual = NativeTargets.requireBlockEntity(chunks, level(), context,
                        blockSelector("block_entity", position), "minecraft:command_block");
                if (!actual.getClass().getName().equals("net.minecraft.world.level.block.entity.CommandBlockEntity")) {
                    throw fail("NATIVE_COMMAND_BLOCK_UNSUPPORTED", "The existing block entity is not the admitted native command block implementation");
                }
                commandBlocks.require(level(), position, actual, context.deepCopy(), execution.deepCopy(),
                        sealedStep.deepCopy(), "command_activation".equals(kind) && instruction.path("auto").booleanValue());
            }
            case "state_initialize", "state_remove" -> requireState(instruction, targets);
            default -> throw invalid();
        }
    }

    @Override public void requireCommand(ObjectNode installedContext, ObjectNode approvedExecution, ObjectNode sealedStep,
                                         int commandIndex, ParseResults<CommandSourceStack> parsed,
                                         List<ObjectNode> exactApprovedTargets, boolean dispatchBoundary) {
        current(installedContext, approvedExecution);
        requireSealedStep(sealedStep);
        if (dispatchBoundary) pending = null;
        if (commandIndex < 0 || commandIndex >= sealedStep.path("encoded_commands").size()
                || !sealedStep.path("encoded_commands").get(commandIndex).isTextual()
                || !sealedStep.path("encoded_commands").get(commandIndex).textValue().equals(parsed.getReader().getString())
                || parsed.getReader().canRead() || !parsed.getExceptions().isEmpty()) throw invalid();
        NativeSceneExecutor.requireOperationSignature(sealedStep, commandIndex, parsed.getReader().getString());
        ObjectNode instruction = object(sealedStep, "instruction");
        ParsedValues values = parsedValues(parsed, instruction);
        switch (text(instruction, "kind")) {
            case "display" -> requireDisplayNbt(instruction, values.compound());
            case "display_pose" -> requireDisplayPoseNbt(instruction, values.compound());
            case "block" -> {
                BlockInput block = values.block();
                if (!block.getState().equals(NativeBlocks.decode(instruction.get("state")))) throw invalid();
                // The exact closed operation signature admits no block-NBT suffix. BlockInput exposes
                // state and properties, but deliberately has no public NBT getter in this target API.
                if (parsed.getReader().getString().indexOf('{') >= 0) throw invalid();
            }
            case "command_shell" -> {
                BlockInput block = values.block();
                ObjectNode expectedState = commandState(instruction);
                if (!block.getState().equals(NativeBlocks.decode(expectedState))) throw invalid();
                // The complete exact shell suffix is independently fixed by the admitted codec signature.
                // No inaccessible BlockInput field is reflected into an invented native observation.
                if (!parsed.getReader().getString().endsWith("{Command:\"\",auto:0b,TrackOutput:0b}")) throw invalid();
            }
            case "command_data" -> {
                CompoundTag tag = values.compound(); requireFields(tag, Set.of("Command", "auto", "TrackOutput"));
                requireString(tag.get("Command"), text(instruction, "source"));
                requireByte(tag.get("auto"), (byte) 0); requireByte(tag.get("TrackOutput"), (byte) 0);
            }
            case "command_activation" -> {
                CompoundTag tag = values.compound(); requireFields(tag, Set.of("auto"));
                requireByte(tag.get("auto"), instruction.path("auto").booleanValue() ? (byte) 1 : (byte) 0);
            }
            case "state_initialize" -> {
                if ("storage_nbt".equals(text(instruction, "storage_kind"))) requireScalar(values.scalar(), instruction);
                else if (commandIndex == 1) {
                    Object value = values.argument("score");
                    int desired = instruction.path("value").isBoolean() ? (instruction.path("value").booleanValue() ? 1 : 0)
                            : instruction.path("value").intValue();
                    if (!(value instanceof Integer integer) || integer != desired) throw invalid();
                }
            }
            case "state_remove", "display_remove" -> { }
            default -> throw invalid();
        }
        // The same actual target guards are applied again before dispatch, rather than admitting a parsed
        // command solely because its text or typed argument happens to look like a native operation.
        if (dispatchBoundary) {
            requireInstruction(installedContext, approvedExecution, sealedStep, exactApprovedTargets, true);
            pending = new PendingDispatch(parsed, sealedStep.deepCopy(), commandIndex, removal, pose);
            removal = null; pose = null;
        }
    }

    @Override public int dispatch(ParseResults<CommandSourceStack> parsed) throws CommandSyntaxException {
        current(context, execution);
        PendingDispatch prepared = pending; pending = null;
        if (prepared == null || prepared.parsed() != parsed) {
            throw fail("NATIVE_DISPATCH_NOT_PREPARED", "Native dispatch requires the exact immediately guarded parsed command");
        }
        if (prepared.commandIndex() < 0 || prepared.commandIndex() >= prepared.sealedStep().path("encoded_commands").size()
                || !prepared.sealedStep().path("encoded_commands").get(prepared.commandIndex()).textValue().equals(parsed.getReader().getString())
                || parsed.getReader().canRead() || !parsed.getExceptions().isEmpty()) throw invalid();
        parsedValues(parsed, object(prepared.sealedStep(), "instruction"));
        NativeSceneExecutor.requireOperationSignature(prepared.sealedStep(), prepared.commandIndex(), parsed.getReader().getString());
        if (prepared.pose() != null) {
            OwnedPose owned = prepared.pose();
            Entity actual = NativeTargets.requireOwnedEntity(chunks, entities, level(), context, owned.actual().getUUID(),
                    owned.expectedType(), owned.ownerTag());
            if (actual != owned.actual()) throw fail("TARGET_IDENTITY_MISMATCH", "The retained pose target is a different actual entity instance");
            NativeTargets.Observation fresh = inspect(owned.selector());
            if (!fresh.sha256().equals(owned.beforeSha256())) throw fail("TARGET_DRIFT", "The retained pose target changed before native dispatch");
        }
        if (prepared.removal() != null) {
            OwnedRemoval owned = prepared.removal();
            Entity actual = NativeTargets.requireOwnedEntity(chunks, entities, level(), context, owned.actual().getUUID(),
                    owned.expectedType(), owned.ownerTag());
            if (actual != owned.actual()) throw fail("TARGET_IDENTITY_MISMATCH", "The retained removal target is a different actual entity instance");
            NativeTargets.Observation fresh = inspect(owned.selector());
            if (!fresh.sha256().equals(owned.beforeSha256())) throw fail("TARGET_DRIFT", "The retained removal target changed before native dispatch");
            tombstones.recordDispatchAttempt(invocation, context.deepCopy(), level(), actual, fresh.sha256(), owned.ownerTag());
        }
        return dispatcher.execute(parsed);
    }

    private void current(ObjectNode installedContext, ObjectNode approvedExecution) {
        if (!server.isSameThread()) throw fail("WRONG_THREAD", "Native execution guards require the actual server thread");
        if (!context.equals(installedContext) || !execution.equals(approvedExecution)) {
            throw fail("INVOCATION_APPROVAL_MISMATCH", "The native guard is bound to one immutable installed context and execution");
        }
        if (server.getPlayerList().getPlayer(player.getUUID()) != player || player.isRemoved()
                || player.level() != level() || !text(context, "executorHandle").equals("player-" + player.getUUID())) {
            throw fail("EXECUTOR_CONTEXT_CHANGED", "The actual paired player no longer owns the installed execution context");
        }
        admission.require(context.deepCopy(), execution.deepCopy());
    }

    private void requireSealedStep(ObjectNode candidate) {
        int matching = 0;
        for (JsonNode step : execution.path("steps")) if (candidate.equals(step)) matching++;
        if (matching != 1 || !candidate.path("encoded_commands").isArray()
                || !text(candidate, "commandDigest").equals(ContractJson.digest(candidate.path("encoded_commands")))) {
            throw fail("INVOCATION_APPROVAL_MISMATCH", "The guarded native step is not an exact unique member of this immutable execution");
        }
    }

    private List<ObservedTarget> targets(ObjectNode approvedExecution, List<ObjectNode> selected) {
        if (selected.isEmpty() || selected.size() > MAX_TARGETS) throw invalid();
        List<ObservedTarget> result = new ArrayList<>(); Set<String> identities = new HashSet<>();
        for (ObjectNode record : selected) {
            boolean admitted = false;
            for (JsonNode candidate : approvedExecution.path("observedTargets")) admitted |= record.equals(candidate);
            if (!admitted) throw fail("NATIVE_FOOTPRINT_MISMATCH", "The native target is not an exact approved observation record");
            ObjectNode selector = object(record, "selector");
            if (!identities.add(ContractJson.digest(selector))) throw invalid();
            if (selector.has("resourceId")) requireResourceMapping(approvedExecution, selector);
            NativeTargets.Observation observed = inspect(selector);
            if (!selector.equals(observed.raw().get("selector"))) throw invalid();
            result.add(new ObservedTarget(record.deepCopy(), selector, observed.raw()));
        }
        return List.copyOf(result);
    }

    private void requireSpawn(ObjectNode instruction, List<ObservedTarget> targets) {
        ObservedTarget target = only(targets, "entity"); requireEntitySelector(instruction, target.selector());
        if (!target.record().path("ownerTag").isTextual()
                || !text(instruction, "tag").equals(text(target.record(), "ownerTag"))) throw invalid();
        ObjectNode raw = target.raw();
        if (!"unknown".equals(raw.path("status").asText()) || !"unknown".equals(raw.path("presence").asText())
                || !"loaded_uuid_not_observed".equals(raw.path("reason").asText())) {
            throw fail("ENTITY_UUID_COLLISION", "Display creation requires a new UUID with no observed loaded identity");
        }
        UUID requested = uuid(instruction.path("uuid"));
        // The shared index includes every observed actual level. It rejects collisions and wrong-level identities.
        if (entities.lookup(level(), requested) != null) throw fail("ENTITY_UUID_COLLISION", "The display UUID already has a loaded entity");
        JsonNode position = instruction.path("position"); int[] block = new int[3];
        for (int axis = 0; axis < 3; axis++) {
            double coordinate = position.path(axis).doubleValue();
            if (!position.path(axis).isNumber() || !Double.isFinite(coordinate) || Math.abs(coordinate) > 30_000_000
                    || coordinate < Integer.MIN_VALUE || coordinate >= (double) Integer.MAX_VALUE + 1) throw invalid();
            block[axis] = (int) Math.floor(coordinate);
        }
        requirePosition(new BlockPos(block[0], block[1], block[2]));
        // This is a bounded loaded-location spawn attempt. It makes no assertion about unloaded persistent UUIDs.
    }

    private void requireRemoval(ObjectNode instruction, List<ObservedTarget> targets, boolean dispatchBoundary) {
        ObservedTarget target = only(targets, "entity"); requireEntitySelector(instruction, target.selector());
        requireFull(target.raw());
        if (!"present".equals(target.raw().path("presence").asText()) || !target.record().path("ownerTag").isTextual()) {
            throw fail("OWNERSHIP_UNPROVEN", "Display removal requires the actual retained owned entity");
        }
        Entity actual = NativeTargets.requireOwnedEntity(chunks, entities, level(), context, uuid(instruction.path("uuid")),
                text(target.selector(), "expectedType"), text(target.record(), "ownerTag"));
        requirePosition(actual.blockPosition());
        if (dispatchBoundary) {
            removal = new OwnedRemoval(actual, target.selector().deepCopy(), ContractJson.digest(target.raw()),
                    text(target.selector(), "expectedType"), text(target.record(), "ownerTag"));
        }
    }

    private void requirePose(ObjectNode instruction, List<ObservedTarget> targets, boolean dispatchBoundary) {
        ObservedTarget target = only(targets, "entity"); requireEntitySelector(instruction, target.selector());
        requireFull(target.raw());
        if (!"present".equals(target.raw().path("presence").asText()) || !target.record().path("ownerTag").isTextual()
                || !text(instruction, "tag").equals(text(target.record(), "ownerTag"))) {
            throw fail("OWNERSHIP_UNPROVEN", "Display pose requires the actual retained entity and its exact sealed ownership tag");
        }
        Entity actual = NativeTargets.requireOwnedEntity(chunks, entities, level(), context, uuid(instruction.path("uuid")),
                text(target.selector(), "expectedType"), text(instruction, "tag"));
        requirePosition(actual.blockPosition());
        if (dispatchBoundary) {
            pose = new OwnedPose(actual, target.selector().deepCopy(), ContractJson.digest(target.raw()),
                    text(target.selector(), "expectedType"), text(instruction, "tag"));
        }
    }

    private void requirePair(List<ObservedTarget> targets, BlockPos position) {
        if (targets.size() != 2) throw invalid();
        ObservedTarget state = one(targets, "block_state"), entity = one(targets, "block_entity");
        if (!state.selector().equals(blockSelector("block_state", position))
                || !entity.selector().equals(blockSelector("block_entity", position))) throw invalid();
        requireFull(entity.raw());
        if (!"known".equals(state.raw().path("status").asText())
                || !"present".equals(state.raw().path("presence").asText())
                || !"native_block_state".equals(state.raw().path("captureScope").asText())
                || !state.raw().path("payload").path("blockState").equals(entity.raw().path("payload").path("blockState"))) {
            throw fail("NATIVE_BEFORE_INCOMPLETE", "Block state and complete native block-entity capture do not describe one actual target");
        }
        String coverage = state.raw().path("coverage").asText();
        boolean hasEntity = state.raw().path("payload").path("hasBlockEntity").booleanValue();
        if (!"full_target".equals(coverage) && !(hasEntity && "tracked_changes_only".equals(coverage)
                && "present".equals(entity.raw().path("presence").asText()))) throw invalid();
    }

    private void requireActivationTargets(ObjectNode approval, ObjectNode step, List<ObservedTarget> targets,
                                          BlockPos position) {
        List<ObservedTarget> direct = new ArrayList<>(); Set<String> required = new HashSet<>();
        for (ObjectNode selector : NativeSceneExecutor.activationEffects(approval, step)) {
            if (!Set.of("score", "storage").contains(selector.path("kind").asText())
                    || !required.add(ContractJson.digest(selector))) throw invalid();
        }
        Set<String> found = new HashSet<>();
        for (ObservedTarget target : targets) {
            String kind = target.selector().path("kind").asText();
            if (Set.of("block_state", "block_entity").contains(kind)) {
                direct.add(target);
                continue;
            }
            String identity = ContractJson.digest(target.selector());
            if (!Set.of("score", "storage").contains(kind) || !required.contains(identity)
                    || !found.add(identity) || !target.record().path("ownerTag").isNull()) {
                throw fail("NATIVE_FOOTPRINT_MISMATCH", "Native activation has an extra or conflicting source-effect target");
            }
            requireResourceMapping(approval, target.selector());
            NativeTargets.Observation fresh = inspect(target.selector()); ObjectNode raw = fresh.raw();
            if (!target.selector().equals(raw.get("selector")) || !raw.equals(target.raw())
                    || !fresh.sha256().equals(ContractJson.sha256(fresh.bytes()))
                    || !fresh.sha256().equals(ContractJson.digest(raw))) {
                throw fail("TARGET_DRIFT", "Native activation source-effect target changed during its guarded observation");
            }
            requireFull(raw);
            String membership = "score".equals(kind) ? "current_native_scoreboard" : "current_cached_command_storage";
            String capture = "score".equals(kind) ? "native_score_entry" : "native_storage_key";
            if (!membership.equals(raw.path("membershipScope").asText())
                    || !capture.equals(raw.path("captureScope").asText())) {
                throw fail("NATIVE_BEFORE_INCOMPLETE", "Native activation source-effect target lacks its exact full native capture");
            }
        }
        if (!found.equals(required)) {
            throw fail("NATIVE_FOOTPRINT_MISMATCH", "Native activation is missing an approved source-effect target");
        }
        requirePair(direct, position);
    }

    private void requireState(ObjectNode instruction, List<ObservedTarget> targets) {
        if ("storage_nbt".equals(text(instruction, "storage_kind"))) {
            ObservedTarget target = only(targets, "storage"); ObjectNode selector = target.selector();
            if (!text(instruction, "storage").equals(selector.path("storage").asText())
                    || !text(instruction, "key").equals(selector.path("key").asText())) throw invalid();
            requireFull(target.raw());
            if (!"current_cached_command_storage".equals(target.raw().path("membershipScope").asText())
                    || !"native_storage_key".equals(target.raw().path("captureScope").asText())) throw invalid();
            return;
        }
        if (!"scoreboard".equals(text(instruction, "storage_kind")) || targets.size() != 2) throw invalid();
        ObservedTarget objective = one(targets, "objective"), score = one(targets, "score");
        if (!text(instruction, "objective").equals(objective.selector().path("objective").asText())
                || !text(instruction, "objective").equals(score.selector().path("objective").asText())
                || !text(instruction, "holder").equals(score.selector().path("holder").asText())) throw invalid();
        requireFull(objective.raw()); requireFull(score.raw());
        if (!"native_objective_and_all_scores".equals(objective.raw().path("captureScope").asText())
                || !"native_score_entry".equals(score.raw().path("captureScope").asText())) {
            throw fail("NATIVE_BEFORE_INCOMPLETE", "Scoreboard mutation requires all objective holders, native metadata and display slots");
        }
    }

    private void requireResourceMapping(ObjectNode approval, ObjectNode selector) {
        String resource = text(selector, "resourceId"); boolean installed = false, scoped = false; int exact = 0;
        for (JsonNode id : context.path("scope").path("resourceIds")) installed |= resource.equals(id.asText());
        for (JsonNode id : approval.path("targetScope").path("resourceIds")) scoped |= resource.equals(id.asText());
        for (JsonNode mapping : approval.path("resourceTargets")) {
            if (selector.equals(mapping.get("selector"))) {
                if (!resource.equals(mapping.path("resourceId").asText())) throw invalid(); exact++;
            }
        }
        if (!installed || !scoped || exact != 1) throw fail("SCOPE_DENIED", "Native state access has no exact installed resource association");
        resources.require(context.deepCopy(), selector.deepCopy());
    }

    private BlockPos requirePosition(ObjectNode instruction) { return requirePosition(NativeBlocks.position(instruction.path("position"))); }
    private BlockPos requirePosition(BlockPos position) {
        NativeBlocks.requireScope(context, text(context, "dimension"), position);
        ObjectNode narrowed = context.deepCopy(); narrowed.set("scope", execution.get("targetScope").deepCopy());
        NativeBlocks.requireScope(narrowed, text(context, "dimension"), position); chunks.require(level(), position);
        return position;
    }

    private ServerLevel level() {
        for (ServerLevel candidate : server.getAllLevels()) {
            if (candidate.dimension().identifier().toString().equals(text(context, "dimension"))) return candidate;
        }
        throw fail("DIMENSION_UNKNOWN", "The installed dimension is not an actual server level");
    }

    private ObjectNode blockSelector(String kind, BlockPos position) {
        ObjectNode result = ContractJson.newObject().put("kind", kind).put("dimension", text(context, "dimension"));
        result.putArray("position").add(position.getX()).add(position.getY()).add(position.getZ()); return result;
    }

    private static boolean hasEarlierShell(ObjectNode approval, ObjectNode step, ObjectNode instruction) {
        for (JsonNode candidate : approval.path("steps")) {
            if (candidate.equals(step)) return false;
            JsonNode preceding = candidate.path("instruction");
            if ("command_shell".equals(preceding.path("kind").asText()) && "stage".equals(candidate.path("phase").asText())
                    && instruction.path("dimension").equals(preceding.path("dimension"))
                    && instruction.path("position").equals(preceding.path("position"))) {
                boolean sameSource = true;
                for (String field : Set.of("source_object_id", "source_node_id", "instance_id", "owner_prefab_id")) {
                    sameSource &= step.path(field).equals(candidate.path(field));
                }
                if (sameSource) return true;
            }
        }
        return false;
    }

    private static void requireEntitySelector(ObjectNode instruction, ObjectNode selector) {
        if (!"entity".equals(selector.path("kind").asText())
                || !text(instruction, "dimension").equals(selector.path("dimension").asText())
                || !uuid(instruction.path("uuid")).toString().equals(selector.path("uuid").asText())
                || !("minecraft:" + text(instruction, "entity_kind") + "_display").equals(selector.path("expectedType").asText())) throw invalid();
    }

    private static void requireFull(ObjectNode raw) {
        if (!"known".equals(raw.path("status").asText()) || !"full_target".equals(raw.path("coverage").asText())
                || !Set.of("present", "absent").contains(raw.path("presence").asText())) {
            throw fail("NATIVE_BEFORE_INCOMPLETE", "This native instruction requires a complete actual target capture");
        }
    }

    private static ObservedTarget only(List<ObservedTarget> values, String kind) {
        if (values.size() != 1) throw invalid(); return one(values, kind);
    }
    private static ObservedTarget one(List<ObservedTarget> values, String kind) {
        ObservedTarget result = null;
        for (ObservedTarget value : values) if (kind.equals(value.selector().path("kind").asText())) {
            if (result != null) throw invalid(); result = value;
        }
        if (result == null) throw invalid(); return result;
    }

    private static ObjectNode commandState(ObjectNode instruction) {
        String block = switch (text(instruction, "command_kind")) {
            case "impulse" -> "command_block"; case "chain" -> "chain_command_block"; case "repeating" -> "repeating_command_block";
            default -> throw invalid();
        };
        ObjectNode state = ContractJson.newObject().put("blockId", "minecraft:" + block);
        state.putObject("properties").put("facing", text(instruction, "facing"))
                .put("conditional", Boolean.toString(instruction.path("conditional").booleanValue())); return state;
    }

    private static ParsedValues parsedValues(ParseResults<CommandSourceStack> parsed, ObjectNode instruction) {
        List<Object> arguments = new ArrayList<>(); List<CommandContextBuilder<CommandSourceStack>> contexts = new ArrayList<>();
        Set<String> allowed = literals(instruction); int nodes = 0, depth = 0;
        for (CommandContextBuilder<CommandSourceStack> builder = parsed.getContext(); builder != null; builder = builder.getChild()) {
            if (++depth > 32) throw invalid(); contexts.add(builder);
            for (var parsedNode : builder.getNodes()) {
                if (++nodes > MAX_COMMAND_NODES) throw invalid(); CommandNode<CommandSourceStack> node = parsedNode.getNode();
                if (node.getClass() == LiteralCommandNode.class) {
                    if (!allowed.contains(node.getName())) throw invalid();
                } else if (node.getClass() == ArgumentCommandNode.class) {
                    Object parser = ((ArgumentCommandNode<CommandSourceStack, ?>) node).getType();
                    requireArgumentParser(parser.getClass());
                } else throw fail("NATIVE_COMMAND_IMPLEMENTATION_UNSUPPORTED", "Parsed command uses an unapproved node implementation");
                if (node.getCommand() != null) requireCommandOwner(node.getCommand().getClass());
                if (node.getRedirectModifier() != null) requireRedirectOwner(node.getRedirectModifier().getClass());
                if (!node.canUse(builder.getSource())) throw fail("PERMISSION_DENIED", "The actual native command node is no longer permitted");
            }
            builder.getArguments().values().forEach(argument -> arguments.add(argument.getResult()));
            if (builder.getCommand() != null) requireCommandOwner(builder.getCommand().getClass());
        }
        if (contexts.isEmpty() || contexts.getLast().getCommand() == null) throw invalid();
        return new ParsedValues(List.copyOf(arguments), List.copyOf(contexts));
    }

    private static Set<String> literals(ObjectNode instruction) {
        return switch (text(instruction, "kind")) {
            case "display" -> Set.of("execute", "in", "run", "summon");
            case "display_pose" -> Set.of("execute", "in", "as", "if", "entity", "run", "data", "merge");
            case "block", "command_shell" -> Set.of("execute", "in", "run", "setblock");
            case "command_data", "command_activation" -> Set.of("execute", "in", "run", "data", "merge", "block");
            case "display_remove" -> Set.of("execute", "in", "as", "if", "entity", "run", "kill");
            case "state_initialize" -> "scoreboard".equals(text(instruction, "storage_kind"))
                    ? Set.of("scoreboard", "objectives", "add", "players", "set", "execute", "unless", "score", "matches", "run")
                    : Set.of("execute", "unless", "data", "storage", "run", "modify", "set", "value");
            case "state_remove" -> "scoreboard".equals(text(instruction, "storage_kind"))
                    ? Set.of("scoreboard", "players", "reset", "objectives", "remove") : Set.of("data", "remove", "storage");
            default -> throw invalid();
        };
    }

    private static void requireArgumentParser(Class<?> type) {
        String name = type.getName();
        if (name.startsWith("com.mojang.brigadier.arguments.")) {
            if (!Set.of("com.mojang.brigadier.arguments.StringArgumentType", "com.mojang.brigadier.arguments.IntegerArgumentType").contains(name)) throw invalid();
            requireLibraryClass(type, CommandNode.class);
            return;
        }
        if (!Set.of("net.minecraft.commands.arguments.DimensionArgument", "net.minecraft.commands.arguments.ResourceLocationArgument",
                "net.minecraft.commands.arguments.EntitySummonArgument", "net.minecraft.commands.arguments.ResourceArgument",
                "net.minecraft.commands.arguments.coordinates.Vec3Argument", "net.minecraft.commands.arguments.coordinates.BlockPosArgument",
                "net.minecraft.commands.arguments.blocks.BlockStateArgument", "net.minecraft.commands.arguments.CompoundTagArgument",
                "net.minecraft.commands.arguments.NbtTagArgument", "net.minecraft.commands.arguments.NbtPathArgument",
                "net.minecraft.commands.arguments.EntityArgument", "net.minecraft.commands.arguments.ScoreHolderArgument",
                "net.minecraft.commands.arguments.ObjectiveArgument", "net.minecraft.commands.arguments.ObjectiveCriteriaArgument",
                "net.minecraft.commands.arguments.RangeArgument$Ints").contains(name)) {
            throw fail("NATIVE_COMMAND_IMPLEMENTATION_UNSUPPORTED", "Native instruction uses an unapproved argument parser implementation");
        }
        requireGameClass(type);
    }

    private static void requireCommandOwner(Class<?> implementation) {
        Class<?> owner = implementation.getNestHost();
        if (!NATIVE_COMMAND_OWNERS.contains(owner.getName())) {
            throw fail("NATIVE_COMMAND_IMPLEMENTATION_UNSUPPORTED", "Native command handler differs from the admitted platform operation");
        }
        requireGameClass(owner); requireGameClass(implementation);
    }

    private static void requireRedirectOwner(Class<?> implementation) {
        Class<?> owner = implementation.getNestHost();
        if (owner.getName().equals("com.mojang.brigadier.builder.ArgumentBuilder")) {
            requireLibraryClass(owner, CommandNode.class); requireLibraryClass(implementation, CommandNode.class);
        } else requireCommandOwner(implementation);
    }

    private static void requireLibraryClass(Class<?> type, Class<?> library) {
        var actual = type.getProtectionDomain().getCodeSource(); var expected = library.getProtectionDomain().getCodeSource();
        if (type.getClassLoader() != library.getClassLoader() || actual == null || expected == null
                || actual.getLocation() == null || !actual.getLocation().equals(expected.getLocation())) {
            throw fail("NATIVE_COMMAND_IMPLEMENTATION_UNSUPPORTED", "The actual parser implementation differs from the admitted native library source");
        }
    }

    private static void requireGameClass(Class<?> type) {
        var actual = type.getProtectionDomain().getCodeSource(); var game = MinecraftServer.class.getProtectionDomain().getCodeSource();
        if (type.getClassLoader() != MinecraftServer.class.getClassLoader() || actual == null || game == null
                || actual.getLocation() == null || !actual.getLocation().equals(game.getLocation())) {
            throw fail("NATIVE_COMMAND_IMPLEMENTATION_UNSUPPORTED", "The actual native implementation is not from the admitted game runtime source");
        }
        // Runtime source/profile admission remains mandatory: a class name and CodeSource are not transformed-byte evidence.
    }

    private static void requireDisplayNbt(ObjectNode instruction, CompoundTag actual) {
        Set<String> fields = new HashSet<>(DISPLAY_FIELDS); ObjectNode payload = object(instruction, "payload");
        payload.fieldNames().forEachRemaining(key -> { if (!"billboard".equals(key)) fields.add(key); }); requireFields(actual, fields);
        List<Tag> tags = list(actual.get("Tags"));
        if (tags.size() != 1) throw invalid(); requireString(tags.getFirst(), text(instruction, "tag"));
        int[] actualUuid = actual.getIntArray("UUID").orElseThrow(NativeExecutionGuard::invalid);
        UUID desired = uuid(instruction.path("uuid")); ByteBuffer bytes = ByteBuffer.allocate(16)
                .putLong(desired.getMostSignificantBits()).putLong(desired.getLeastSignificantBits()); bytes.flip();
        if (actualUuid.length != 4) throw invalid(); for (int word : actualUuid) if (word != bytes.getInt()) throw invalid();
        requireString(actual.get("billboard"), "fixed");
        List<Tag> rotation = list(actual.get("Rotation"));
        if (rotation.size() != 2) throw invalid(); for (Tag component : rotation) requireFloat(component, 0.0f);
        List<Tag> matrix = list(actual.get("transformation"));
        if (matrix.size() != 16) throw invalid();
        for (int index = 0; index < 16; index++) requireFloat(matrix.get(index), instruction.path("matrix").path(index).floatValue());
        requireInt(actual.get("start_interpolation"), 0); requireInt(actual.get("interpolation_duration"), 0);
        requireInt(actual.get("teleport_duration"), 0);
        int[] budget = {0}; payload.fields().forEachRemaining(entry -> {
            if (!"billboard".equals(entry.getKey())) requirePayload(actual.get(entry.getKey()), entry.getValue(), 0, budget);
        });
    }

    private static void requireDisplayPoseNbt(ObjectNode instruction, CompoundTag actual) {
        requireFields(actual, Set.of("transformation", "interpolation_duration", "start_interpolation", "teleport_duration"));
        List<Tag> matrix = list(actual.get("transformation"));
        if (matrix.size() != 16) throw invalid();
        for (int index = 0; index < 16; index++) requireFloat(matrix.get(index), instruction.path("matrix").path(index).floatValue());
        requireInt(actual.get("interpolation_duration"), 0); requireInt(actual.get("start_interpolation"), 0);
        requireInt(actual.get("teleport_duration"), 0);
    }

    private static void requirePayload(Tag actual, JsonNode desired, int depth, int[] budget) {
        if (++budget[0] > MAX_NBT_NODES || depth > MAX_NBT_DEPTH || actual == null || desired.isNull()) throw invalid();
        if (desired.isObject()) {
            if (!(actual instanceof CompoundTag compound) || desired.size() > MAX_NBT_ENTRIES) throw invalid();
            Set<String> fields = new HashSet<>(); desired.fieldNames().forEachRemaining(fields::add); requireFields(compound, fields);
            desired.fields().forEachRemaining(entry -> requirePayload(compound.get(entry.getKey()), entry.getValue(), depth + 1, budget));
        } else if (desired.isArray()) {
            List<Tag> values = list(actual); if (values.size() != desired.size()) throw invalid();
            for (int index = 0; index < values.size(); index++) requirePayload(values.get(index), desired.get(index), depth + 1, budget);
        } else if (desired.isTextual()) requireString(actual, desired.textValue());
        else if (desired.isBoolean()) requireByte(actual, desired.booleanValue() ? (byte) 1 : (byte) 0);
        else if (desired.isIntegralNumber()) {
            long expected;
            try { expected = desired.bigIntegerValue().longValueExact(); } catch (ArithmeticException exception) { throw invalid(); }
            if (expected >= Integer.MIN_VALUE && expected <= Integer.MAX_VALUE) requireInt(actual, (int) expected);
            else if (actual.getId() != 4 || nativeTag(actual).asLong().orElseThrow(NativeExecutionGuard::invalid) != expected) throw invalid();
        } else if (desired.isFloatingPointNumber()) {
            if (actual.getId() != 6 || Double.doubleToRawLongBits(nativeTag(actual).asDouble().orElseThrow(NativeExecutionGuard::invalid))
                    != Double.doubleToRawLongBits(desired.doubleValue())) throw invalid();
        } else throw invalid();
    }

    private static void requireScalar(Tag actual, ObjectNode instruction) {
        switch (text(instruction, "state_type")) {
            case "boolean" -> requireByte(actual, instruction.path("value").booleanValue() ? (byte) 1 : (byte) 0);
            case "int32" -> requireInt(actual, instruction.path("value").intValue());
            case "float32" -> requireFloat(actual, instruction.path("value").floatValue());
            default -> throw invalid();
        }
    }

    private static void requireString(Tag actual, String desired) {
        if (actual == null || actual.getId() != 8 || !desired.equals(nativeTag(actual).asString().orElseThrow(NativeExecutionGuard::invalid))) throw invalid();
    }
    private static void requireByte(Tag actual, byte desired) {
        if (actual == null || actual.getId() != 1 || nativeTag(actual).asByte().orElseThrow(NativeExecutionGuard::invalid) != desired) throw invalid();
    }
    private static void requireInt(Tag actual, int desired) {
        if (actual == null || actual.getId() != 3 || nativeTag(actual).asInt().orElseThrow(NativeExecutionGuard::invalid) != desired) throw invalid();
    }
    private static void requireFloat(Tag actual, float desired) {
        if (actual == null || actual.getId() != 5 || !Float.isFinite(desired)
                || Float.floatToRawIntBits(nativeTag(actual).asFloat().orElseThrow(NativeExecutionGuard::invalid)) != Float.floatToRawIntBits(desired)) throw invalid();
    }

    private static Tag nativeTag(Tag value) { requireGameClass(value.getClass()); return value; }
    private static List<Tag> list(Tag actual) {
        if (actual == null || actual.getId() != 9 || !(actual instanceof Iterable<?> children)) throw invalid();
        requireGameClass(actual.getClass()); List<Tag> values = new ArrayList<>();
        for (Object value : children) {
            if (values.size() >= MAX_NBT_ENTRIES || !(value instanceof Tag child)) throw invalid(); values.add(child);
        }
        return List.copyOf(values);
    }
    private static void requireFields(CompoundTag actual, Set<String> fields) {
        if (actual == null || actual.size() > MAX_NBT_ENTRIES || !actual.keySet().equals(fields)) throw invalid();
    }

    private static UUID uuid(JsonNode bytes) {
        if (!bytes.isArray() || bytes.size() != 16) throw invalid(); ByteBuffer value = ByteBuffer.allocate(16);
        for (JsonNode element : bytes) {
            if (!element.isIntegralNumber() || !element.canConvertToInt() || element.intValue() < 0 || element.intValue() > 255) throw invalid();
            value.put((byte) element.intValue());
        }
        value.flip(); return new UUID(value.getLong(), value.getLong());
    }
    private static ObjectNode object(ObjectNode value, String field) { return ContractJson.object(value.path(field)); }
    private static String text(ObjectNode value, String field) { if (!value.path(field).isTextual()) throw invalid(); return value.path(field).textValue(); }
    private static ContractException invalid() { return fail("NATIVE_COMMAND_ADMISSION_FAILED", "The sealed instruction does not match its exact admitted native target or parsed command values"); }
    private static ContractException fail(String code, String message) { return new ContractException(code, message); }

    private record ObservedTarget(ObjectNode record, ObjectNode selector, ObjectNode raw) { }
    private record OwnedRemoval(Entity actual, ObjectNode selector, String beforeSha256, String expectedType, String ownerTag) { }
    private record OwnedPose(Entity actual, ObjectNode selector, String beforeSha256, String expectedType, String ownerTag) { }
    private record PendingDispatch(ParseResults<CommandSourceStack> parsed, ObjectNode sealedStep, int commandIndex, OwnedRemoval removal, OwnedPose pose) { }
    private record ParsedValues(List<Object> arguments, List<CommandContextBuilder<CommandSourceStack>> contexts) {
        private CompoundTag compound() {
            CompoundTag result = null;
            for (Object argument : arguments) if (argument instanceof CompoundTag tag) { if (result != null) throw invalid(); result = tag; }
            if (result == null) throw invalid(); return result;
        }
        private BlockInput block() {
            BlockInput result = null;
            for (Object argument : arguments) if (argument instanceof BlockInput value) {
                if (result != null || value.getClass() != BlockInput.class) throw invalid(); requireGameClass(value.getClass()); result = value;
            }
            if (result == null) throw invalid(); return result;
        }
        private Tag scalar() {
            Tag result = null;
            for (Object argument : arguments) if (argument instanceof Tag value) { if (result != null) throw invalid(); result = value; }
            if (result == null) throw invalid(); return result;
        }
        private Object argument(String name) {
            Object result = null;
            for (CommandContextBuilder<CommandSourceStack> builder : contexts) {
                var found = builder.getArguments().get(name);
                if (found != null) { if (result != null) throw invalid(); result = found.getResult(); }
            }
            if (result == null) throw invalid(); return result;
        }
    }
}
