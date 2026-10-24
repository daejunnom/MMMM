package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Set;
import net.minecraft.core.BlockPos;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.BaseCommandBlock;
import net.minecraft.world.level.block.Block;
import net.minecraft.world.level.block.Blocks;
import net.minecraft.world.level.block.entity.BlockEntity;
import net.minecraft.world.level.block.entity.CommandBlockEntity;
import net.minecraft.world.level.block.state.BlockState;
import net.minecraft.world.ticks.LevelChunkTicks;
import net.minecraft.world.ticks.LevelTicks;

/**
 * Reads actual loaded command-block state. It never schedules, removes ticks, changes source,
 * sets automatic/powered, loads a chunk or treats an approved desired value as native readback.
 */
final class NativeCommandBlockFence implements NativeExecutionGuard.CommandBlockAuthority {
    private static final int MAX_SOURCE_BYTES = 16_384;
    private static final Set<String> OWNER_FIELDS = Set.of("source_object_id", "source_node_id", "instance_id", "owner_prefab_id");

    /**
     * A trusted retained Rust authority must approve this exact actual command source, its complete
     * indirect effect closure and this native activation operation against the immutable original
     * plan. Implementations inspect only; an administrator flag, hash or auto:0 is insufficient.
     */
    @FunctionalInterface
    interface TrustedActivation {
        void require(Activation request);

        static TrustedActivation unavailable() {
            return request -> { throw failure("NATIVE_COMMAND_SOURCE_UNAPPROVED",
                    "The exact command-block source and indirect effect closure have no retained trusted approval"); };
        }
    }

    /** Frozen approval values plus actual native receivers, valid only during the same-thread check. */
    static final class Activation {
        private final Invocation invocation;
        private final ObjectNode originalManifest;
        private final ObjectNode context;
        private final ObjectNode execution;
        private final ObjectNode step;
        private final ObjectNode shell;
        private final ObjectNode data;
        private final ServerLevel level;
        private final BlockPos position;
        private final CommandBlockEntity actual;
        private final BaseCommandBlock receiver;
        private final String rawSource;
        private final String nativeOperation;

        private Activation(Invocation invocation, ObjectNode originalManifest, ObjectNode context,
                           ObjectNode execution, ObjectNode step, Definition definition, ServerLevel level,
                           BlockPos position, CommandBlockEntity actual, BaseCommandBlock receiver,
                           String rawSource, String nativeOperation) {
            this.invocation = invocation;
            this.originalManifest = originalManifest.deepCopy(); this.context = context.deepCopy();
            this.execution = execution.deepCopy(); this.step = step.deepCopy();
            this.shell = definition.shell().deepCopy(); this.data = definition.data().deepCopy();
            this.level = level; this.position = copy(position); this.actual = actual; this.receiver = receiver;
            this.rawSource = rawSource; this.nativeOperation = nativeOperation;
        }

        Invocation invocation() { return invocation; }
        ObjectNode originalPlanManifest() { return originalManifest.deepCopy(); }
        ObjectNode installedContext() { return context.deepCopy(); }
        ObjectNode approvedExecution() { return execution.deepCopy(); }
        ObjectNode sealedStep() { return step.deepCopy(); }
        ObjectNode sealedShell() { return shell.deepCopy(); }
        ObjectNode sealedData() { return data.deepCopy(); }
        ServerLevel level() { return level; }
        BlockPos position() { return copy(position); }
        CommandBlockEntity actualBlockEntity() { return actual; }
        BaseCommandBlock actualCommandReceiver() { return receiver; }
        String exactRawSource() { return rawSource; }
        String exactNativeOperation() { return nativeOperation; }
    }

    private final MinecraftServer server;
    private final LoadedChunks chunks;
    private final Invocation invocation;
    private final ObjectNode context;
    private final ObjectNode manifest;
    private final ObjectNode execution;
    private final NativeExecutionGuard.CurrentAdmission liveAdmission;
    private final TrustedActivation activationAuthority;

    NativeCommandBlockFence(MinecraftServer server, LoadedChunks chunks, Invocation invocation,
                            NativePlanApproval originalApproval, ObjectNode approvedExecution,
                            NativeExecutionGuard.CurrentAdmission liveAdmission, TrustedActivation activationAuthority) {
        this.server = Objects.requireNonNull(server); this.chunks = Objects.requireNonNull(chunks);
        this.invocation = Objects.requireNonNull(invocation); this.context = invocation.context();
        this.manifest = Objects.requireNonNull(originalApproval).manifest();
        this.execution = ContractJson.object(ContractJson.parse(ContractJson.bytes(Objects.requireNonNull(approvedExecution))));
        this.liveAdmission = Objects.requireNonNull(liveAdmission);
        this.activationAuthority = Objects.requireNonNull(activationAuthority);
        requireManifestBinding();
    }

    /** Compose this immutable-plan check with the actual installed lifecycle/profile authority. */
    NativeExecutionGuard.CurrentAdmission admissionClosure() { return this::requireCurrent; }

    @Override public void require(ServerLevel level, BlockPos position, BlockEntity actual,
                                  ObjectNode installedContext, ObjectNode approvedExecution,
                                  ObjectNode sealedStep, boolean activation) {
        requireCurrent(installedContext, approvedExecution);
        Objects.requireNonNull(level); Objects.requireNonNull(position);
        if (level.getServer() != server || !level.dimension().identifier().toString().equals(text(context, "dimension"))) {
            throw failure("CONTEXT_SCOPE_MISMATCH", "The actual command-block level differs from the installed context");
        }
        int currentLevels = 0; int scannedLevels = 0;
        for (ServerLevel currentLevel : server.getAllLevels()) {
            if (++scannedLevels > NativePlanApproval.MAX_STEPS) throw failure("NATIVE_LEVEL_LIMIT", "Native level identity inspection exceeds its finite budget");
            if (currentLevel.dimension().identifier().toString().equals(text(context, "dimension"))) {
                if (currentLevel != level) throw failure("CONTEXT_SCOPE_MISMATCH", "The supplied command-block level is not the actual installed native level instance");
                currentLevels++;
            }
        }
        if (currentLevels != 1) throw failure("CONTEXT_SCOPE_MISMATCH", "The installed command-block level is not uniquely present in the actual server");
        ObjectNode instruction = instruction(sealedStep);
        requireStep(sealedStep);
        String kind = text(instruction, "kind");
        if (!Set.of("command_shell", "command_data", "command_activation").contains(kind)
                || !position.equals(NativeBlocks.position(instruction.get("position")))
                || !level.dimension().identifier().toString().equals(text(instruction, "dimension"))) throw mismatch();
        boolean activates = "command_activation".equals(kind) && instruction.path("auto").isBoolean()
                && instruction.get("auto").booleanValue();
        if (activation != activates || "command_activation".equals(kind) && !instruction.path("auto").isBoolean()) throw mismatch();

        NativeBlocks.requireScope(context, text(instruction, "dimension"), position);
        ObjectNode targetContext = context.deepCopy(); targetContext.set("scope", execution.path("targetScope").deepCopy());
        NativeBlocks.requireScope(targetContext, text(instruction, "dimension"), position);
        var chunk = chunks.require(level, position);
        BlockState state = chunk.getBlockState(position);
        BlockEntity current = chunk.getBlockEntities().get(position);
        if (current != actual) throw failure("TARGET_IDENTITY_MISMATCH", "The command-block fence received a different actual loaded block entity");
        requireNoNativeTicks(level, position);

        if ("command_shell".equals(kind) && actual == null) {
            if (state.hasBlockEntity()) throw failure("NATIVE_COMMAND_BLOCK_UNSUPPORTED", "Shell staging cannot replace an unresolved actual block entity");
            return;
        }
        CommandBlockEntity block = requireActual(level, position, actual, state);
        ObjectNode shell = "command_shell".equals(kind) ? sealedStep : definition(sealedStep, kind).shell();
        requireShellState(block, state, instruction(shell));
        requireQuiescent(level, position, block);
        BaseCommandBlock receiver = block.getCommandBlock();
        if (receiver == null || !receiver.getClass().getName().equals("net.minecraft.world.level.block.entity.CommandBlockEntity$1")) {
            throw failure("NATIVE_COMMAND_BLOCK_UNSUPPORTED", "The actual command receiver is not the admitted native implementation");
        }
        String rawSource = receiver.getCommand();
        requireSource(rawSource);
        if ("command_shell".equals(kind) || "command_data".equals(kind)) {
            if (!rawSource.isEmpty()) throw failure("NATIVE_COMMAND_SOURCE_OPAQUE", "Staging cannot replace a previously installed nonempty command-block source");
            if ("command_data".equals(kind)) requireSource(text(instruction, "source"));
            return;
        }

        Definition definition = definition(sealedStep, kind);
        if (!rawSource.equals(text(instruction(definition.data()), "source"))) {
            throw failure("NATIVE_COMMAND_SOURCE_MISMATCH", "The actual raw command-block source differs from the exact original approved data step");
        }
        if (activates) {
            String nativeOperation = nativeOperation(sealedStep);
            activationAuthority.require(new Activation(invocation, manifest, context, execution, sealedStep,
                    definition, level, position, block, receiver, rawSource, nativeOperation));
            // The authority is a read-only port. Recheck actual state after it returns before admission.
            requireCurrent(installedContext, approvedExecution);
            BlockState afterState = chunks.require(level, position).getBlockState(position);
            if (chunks.require(level, position).getBlockEntities().get(position) != block
                    || !state.equals(afterState) || block.getCommandBlock() != receiver
                    || !rawSource.equals(receiver.getCommand())) {
                throw failure("TARGET_DRIFT", "Actual command-block identity or raw source changed during trusted activation admission");
            }
            requireActual(level, position, block, afterState);
            requireShellState(block, afterState, instruction(definition.shell()));
            requireQuiescent(level, position, block);
        }
    }

    private void requireCurrent(ObjectNode installedContext, ObjectNode approvedExecution) {
        if (!server.isSameThread()) throw failure("WRONG_THREAD", "Command-block admission requires the actual server thread");
        if (!context.equals(installedContext) || !execution.equals(approvedExecution)) throw mismatch();
        requireManifestBinding();
        liveAdmission.require(context.deepCopy(), execution.deepCopy());
    }

    private void requireManifestBinding() {
        if (!text(manifest, "principalId").equals(text(context, "principalRef"))
                || !text(manifest, "projectId").equals(text(context, "projectId"))
                || !text(manifest, "policyRevision").equals(text(context, "policyRevision"))
                || !text(execution, "stepId").equals(invocation.stepId())
                || !text(execution, "argumentsDigest").equals(invocation.argumentsDigest())) throw mismatch();
        int executions = 0;
        for (JsonNode candidate : manifest.path("nativeExecutions")) if (execution.equals(candidate)) executions++;
        int steps = 0;
        for (JsonNode candidate : manifest.path("steps")) {
            if (!invocation.stepId().equals(candidate.path("stepId").asText())) continue;
            if (!invocation.bindingId().equals(candidate.path("bindingId").asText())
                    || !invocation.actionId().equals(candidate.path("actionId").asText())
                    || !invocation.actionDigest().equals(candidate.path("actionDigest").asText())
                    || !invocation.implementationDigest().equals(candidate.path("implementationDigest").asText())
                    || !invocation.argumentsDigest().equals(candidate.path("argumentsDigest").asText())
                    || !invocation.contextId().equals(candidate.path("contextId").asText())
                    || !invocation.contextDigest().equals(candidate.path("contextDigest").asText())) throw mismatch();
            steps++;
        }
        if (executions != 1 || steps != 1) throw mismatch();
    }

    private void requireStep(ObjectNode step) {
        int matches = 0;
        for (JsonNode candidate : execution.path("steps")) if (step.equals(candidate)) matches++;
        if (matches != 1 || !text(step, "commandDigest").equals(ContractJson.digest(step.path("encoded_commands")))) throw mismatch();
        nativeOperation(step);
    }

    private Definition definition(ObjectNode selectedStep, String kind) {
        ObjectNode selectedInstruction = instruction(selectedStep);
        ObjectNode shell = null; ObjectNode data = null;
        for (JsonNode executionNode : manifest.path("nativeExecutions")) {
            ObjectNode sourceExecution = ContractJson.object(executionNode);
            for (JsonNode stepNode : sourceExecution.path("steps")) {
                ObjectNode step = ContractJson.object(stepNode);
                ObjectNode candidate = instruction(step);
                if (!sameTarget(selectedStep, step) || !"stage".equals(step.path("phase").asText())) continue;
                switch (candidate.path("kind").asText()) {
                    case "command_shell" -> {
                        if (shell != null) throw failure("NATIVE_COMMAND_DEFINITION_AMBIGUOUS", "The original plan has multiple command shells for this exact native target");
                        shell = step;
                    }
                    case "command_data" -> {
                        if (data != null) throw failure("NATIVE_COMMAND_DEFINITION_AMBIGUOUS", "The original plan has multiple command sources for this exact native target");
                        data = step;
                    }
                    default -> { }
                }
            }
        }
        if (shell == null || data == null || !sameTarget(shell, data)) {
            throw failure("NATIVE_COMMAND_DEFINITION_UNAVAILABLE", "The original plan has no exact shell and raw data definition for this command block");
        }
        if ("command_data".equals(kind)) {
            if (!selectedStep.equals(data) || !earlierShell(shell, selectedStep)) throw mismatch();
        } else if (!"command_activation".equals(kind) || !selectedInstruction.path("auto").isBoolean()) throw mismatch();
        requireSource(text(instruction(data), "source"));
        return new Definition(shell, data);
    }

    private boolean earlierShell(ObjectNode shell, ObjectNode data) {
        boolean found = false;
        for (JsonNode candidate : execution.path("steps")) {
            if (candidate.equals(data)) return found;
            if (candidate.equals(shell)) found = true;
        }
        return false;
    }

    private static boolean sameTarget(ObjectNode left, ObjectNode right) {
        ObjectNode leftInstruction = instruction(left), rightInstruction = instruction(right);
        if (!leftInstruction.path("dimension").equals(rightInstruction.path("dimension"))
                || !leftInstruction.path("position").equals(rightInstruction.path("position"))) return false;
        for (String field : OWNER_FIELDS) if (!left.path(field).equals(right.path(field))) return false;
        return true;
    }

    private static CommandBlockEntity requireActual(ServerLevel level, BlockPos position, BlockEntity actual, BlockState state) {
        if (actual == null || actual.getClass() != CommandBlockEntity.class || actual.isRemoved()
                || actual.getLevel() != level || !position.equals(actual.getBlockPos())
                || !state.hasBlockEntity() || !state.equals(actual.getBlockState())) {
            throw failure("TARGET_IDENTITY_MISMATCH", "The actual loaded native command-block identity or state no longer matches");
        }
        return (CommandBlockEntity) actual;
    }

    private static void requireShellState(CommandBlockEntity actual, BlockState state, ObjectNode shell) {
        Block expectedBlock; CommandBlockEntity.Mode expectedMode;
        switch (text(shell, "command_kind")) {
            case "impulse" -> { expectedBlock = Blocks.COMMAND_BLOCK; expectedMode = CommandBlockEntity.Mode.REDSTONE; }
            case "chain" -> { expectedBlock = Blocks.CHAIN_COMMAND_BLOCK; expectedMode = CommandBlockEntity.Mode.SEQUENCE; }
            case "repeating" -> { expectedBlock = Blocks.REPEATING_COMMAND_BLOCK; expectedMode = CommandBlockEntity.Mode.AUTO; }
            default -> throw mismatch();
        }
        ObjectNode properties = ContractJson.object(NativeBlocks.state(state).get("properties"));
        if (state.getBlock() != expectedBlock || actual.getMode() != expectedMode
                || !text(shell, "facing").equals(properties.path("facing").asText())
                || !shell.path("conditional").isBoolean()
                || !Boolean.toString(shell.get("conditional").booleanValue()).equals(properties.path("conditional").asText())) {
            throw failure("NATIVE_COMMAND_BLOCK_MODE_MISMATCH", "The actual native command-block mode, facing or conditional state differs from the original shell");
        }
    }

    private void requireQuiescent(ServerLevel level, BlockPos position, CommandBlockEntity actual) {
        if (actual.isAutomatic() || actual.isPowered()) {
            throw failure("NATIVE_COMMAND_BLOCK_ACTIVE", "The actual command block is automatic or powered; a read-only fence cannot make it inactive");
        }
        BaseCommandBlock receiver = actual.getCommandBlock();
        if (receiver == null || receiver.isTrackOutput()) {
            throw failure("NATIVE_COMMAND_BLOCK_STATE_MISMATCH", "The actual command block is not the exact staged no-output shell");
        }
        requireNoNativeTicks(level, position);
    }

    private void requireNoNativeTicks(ServerLevel level, BlockPos position) {
        var ticks = level.getBlockTicks();
        var chunkTicks = chunks.require(level, position).getBlockTicks();
        if (ticks == null || ticks.getClass() != LevelTicks.class
                || chunkTicks == null || chunkTicks.getClass() != LevelChunkTicks.class) {
            throw failure("NATIVE_TICK_STATE_UNAVAILABLE", "Actual native level or loaded chunk tick containers are unavailable or have an unadmitted implementation");
        }
        LevelChunkTicks<Block> pending = (LevelChunkTicks<Block>) chunkTicks;
        // Check all native command-block types: a stale scheduled type must not be hidden by
        // comparing only the currently installed block. The actual chunk set includes saved,
        // not-yet-unpacked ticks even when no level scheduler container is registered. The
        // native level scheduler also owns the separate already-selected current-tick queue.
        for (Block type : new Block[] {Blocks.COMMAND_BLOCK, Blocks.CHAIN_COMMAND_BLOCK, Blocks.REPEATING_COMMAND_BLOCK}) {
            if (pending.hasScheduledTick(position, type) || ticks.hasScheduledTick(position, type)
                    || ticks.willTickThisTick(position, type)) {
                throw failure("NATIVE_COMMAND_BLOCK_TICK_PENDING", "The actual native scheduler has a pending command-block tick at this position");
            }
        }
    }

    private static String nativeOperation(ObjectNode step) {
        JsonNode commands = step.path("encoded_commands");
        if (!commands.isArray() || commands.size() != 1 || !commands.get(0).isTextual()) throw mismatch();
        String operation = commands.get(0).textValue();
        NativeSceneExecutor.requireOperationSignature(step, 0, operation);
        return operation;
    }

    private static void requireSource(String raw) {
        if (raw == null || raw.length() > MAX_SOURCE_BYTES || raw.getBytes(StandardCharsets.UTF_8).length > MAX_SOURCE_BYTES) {
            throw failure("NATIVE_COMMAND_SOURCE_UNSUPPORTED", "The actual raw command-block source exceeds the admitted finite source budget");
        }
    }

    private static ObjectNode instruction(ObjectNode step) { return ContractJson.object(step.get("instruction")); }
    private static BlockPos copy(BlockPos position) { return new BlockPos(position.getX(), position.getY(), position.getZ()); }
    private static String text(ObjectNode value, String field) {
        if (!value.path(field).isTextual()) throw mismatch();
        return value.get(field).textValue();
    }
    private static ContractException mismatch() { return failure("INVOCATION_APPROVAL_MISMATCH", "The command-block fence differs from the exact immutable original approval"); }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
    private record Definition(ObjectNode shell, ObjectNode data) { }
}
