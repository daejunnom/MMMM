package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.List;
import java.util.Set;
import java.util.function.LongSupplier;
import net.minecraft.core.BlockPos;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.block.Blocks;

/** Direct observations of the built-in AIR/STONE codec, never an execution or indirect-effect grant. */
final class OwnedBlockPatchPreflight {
    static final String PRODUCER = "mmmm:vanilla_air_stone_direct_block_patch/v1";
    static final String LOSS = "INDIRECT_ENGINE_EFFECTS_EXCLUDED";
    static final List<String> LIMITATIONS = List.of("conservative_3x3x3_fence_only",
            "entity_poi_lighting_neighbor_effects_not_observed", "indirect_effect_recovery_not_guaranteed",
            "exact_undo_not_supported");
    private static final Set<String> INPUT = Set.of("dimension", "position", "expectedState", "desiredState", "expectedRegistryGeneration");

    private OwnedBlockPatchPreflight() { }

    /** A test port for observation orchestration. Only the adapter below reads actual game objects. */
    record Cell(ObjectNode state, String registryIdentity, boolean blockEntityAbsent, boolean fluidEmpty) {
        Cell { state = state.deepCopy(); }
        @Override public ObjectNode state() { return state.deepCopy(); }
    }
    @FunctionalInterface interface Cells { Cell read(BlockPos position); }

    static ObjectNode inspect(LoadedChunks loaded, ServerLevel level, ObjectNode context, ObjectNode input,
                              ObjectNode facts, String hostDigest, String implementationDigest, String generation,
                              Runnable checkpoint) {
        return observe(context, input, facts, hostDigest, implementationDigest, generation,
                actualCells(loaded, level, checkpoint), () -> Integer.toUnsignedLong(level.getServer().getTickCount()), checkpoint);
    }

    private static Cells actualCells(LoadedChunks loaded, ServerLevel level, Runnable checkpoint) {
        return position -> {
            checkpoint.run();
            var chunk = loaded.require(level, position); checkpoint.run();
            var actual = chunk.getBlockState(position); checkpoint.run();
            String identity = actual.getBlock() == Blocks.AIR && actual == Blocks.AIR.defaultBlockState() ? "vanilla_air"
                    : actual.getBlock() == Blocks.STONE && actual == Blocks.STONE.defaultBlockState() ? "vanilla_stone" : null;
            boolean absent = !actual.hasBlockEntity() && chunk.getBlockEntities().get(position) == null; checkpoint.run();
            boolean fluidEmpty = actual.getFluidState().isEmpty(); checkpoint.run();
            return new Cell(NativeBlocks.state(actual), identity, absent, fluidEmpty);
        };
    }

    /** Getter-only recheck after source/profile callbacks, including beginMutation's own checks. */
    static void requireCurrentCells(LoadedChunks loaded, ServerLevel level, ObjectNode context, ObjectNode input,
                                    String generation, Runnable checkpoint) {
        try {
            checkpoint.run(); validateInput(context, input, generation);
            String reason = readCells(context, input, actualCells(loaded, level, checkpoint), checkpoint).reason();
            checkpoint.run(); if (reason != null) throw failure(reason);
        } catch (RuntimeException failure) {
            try { checkpoint.run(); } catch (RuntimeException current) { if (current != failure) failure.addSuppressed(current); }
            throw failure;
        }
    }

    static ObjectNode observe(ObjectNode context, ObjectNode input, ObjectNode facts, String hostDigest,
                              String implementationDigest, String generation, Cells access, LongSupplier ticks,
                              Runnable checkpoint) {
        checkpoint.run(); validateInput(context, input, generation);
        BlockPos center = NativeBlocks.position(input.path("position"));
        requireDigest(hostDigest); requireDigest(implementationDigest);
        if (!generation.equals(facts.path("registryGeneration").asText()) || !facts.path("environment").equals(context.path("environment"))) throw failure("TARGET_DRIFT");
        ObjectNode result = ContractJson.newObject().put("format", "mmmm.owned-block-footprint/1").put("status", "unsupported")
                .putNull("reasonCode").put("producerId", PRODUCER).put("hostArtifactDigest", hostDigest)
                .put("implementationDigest", implementationDigest).put("profileDigest", ContractJson.digest(profile(hostDigest, implementationDigest)))
                .put("runtimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(facts)).put("registryGeneration", generation)
                .put("contextDigest", context.path("contextDigest").asText()).put("dimension", input.path("dimension").textValue())
                .put("observedFromTick", Long.toString(ticks.getAsLong()));
        result.set("position", position(center)); result.set("expectedState", input.path("expectedState").deepCopy());
        result.set("desiredState", input.path("desiredState").deepCopy()); result.putArray("cells"); result.putNull("conditionsDigest");
        directFields(result);
        try {
            Observed observed = readCells(context, input, access, checkpoint); String reason = observed.reason();
            checkpoint.run(); result.put("observedToTick", Long.toString(ticks.getAsLong()));
            if (reason != null) result.put("reasonCode", reason);
            else {
                result.put("status", "known"); result.set("cells", observed.cells());
                result.put("conditionsDigest", conditionsDigest(result));
            }
            checkpoint.run(); return result;
        } catch (RuntimeException failure) {
            try { checkpoint.run(); } catch (RuntimeException current) { if (current != failure) failure.addSuppressed(current); }
            throw failure;
        }
    }

    private record Observed(ArrayNode cells, String reason) { }
    private static Observed readCells(ObjectNode context, ObjectNode input, Cells access, Runnable checkpoint) {
        String reason = !ownedState(input.path("expectedState")) || !ownedState(input.path("desiredState")) ? "OWNED_BLOCK_STATE_UNSUPPORTED" : null;
        ArrayNode cells = ContractJson.newObject().putArray("cells");
        BlockPos center = NativeBlocks.position(input.path("position"));
        if (reason == null) {
            // This order is part of the private receipt: y, then z, then x; center is index 13.
            outer: for (int y = -1; y <= 1; y++) for (int z = -1; z <= 1; z++) for (int x = -1; x <= 1; x++) {
                checkpoint.run(); BlockPos target;
                try { target = new BlockPos(Math.addExact(center.getX(), x), Math.addExact(center.getY(), y), Math.addExact(center.getZ(), z)); }
                catch (ArithmeticException exception) { throw failure("POSITION_INVALID"); }
                NativeBlocks.requireScope(context, input.path("dimension").textValue(), target);
                Cell cell = access.read(target); checkpoint.run();
                boolean isCenter = x == 0 && y == 0 && z == 0;
                if (cell.registryIdentity() == null || !ownedState(cell.state())) reason = "OWNED_BLOCK_STATE_UNSUPPORTED";
                else if (!cell.blockEntityAbsent()) reason = "OWNED_BLOCK_ENTITY_PRESENT";
                else if (!cell.fluidEmpty()) reason = "OWNED_BLOCK_FLUID_PRESENT";
                else if (isCenter && !cell.state().equals(input.path("expectedState"))) reason = "OWNED_BLOCK_EXPECTED_STATE_CHANGED";
                else if (!isCenter && !"vanilla_air".equals(cell.registryIdentity())) reason = "OWNED_BLOCK_NEIGHBOR_NOT_AIR";
                if (reason != null) break outer;
                ObjectNode observed = ContractJson.newObject().put("registryIdentity", cell.registryIdentity()).put("blockEntityAbsent", true).put("fluidEmpty", true);
                observed.set("position", position(target)); observed.set("state", cell.state()); cells.add(observed);
            }
        }
        return new Observed(cells, reason);
    }

    static void validateInput(ObjectNode context, ObjectNode input, String generation) {
        HostDispatcher.exactFields(input, INPUT);
        if (generation == null || !generation.matches("^(0|[1-9][0-9]{0,18})$") || !input.path("expectedRegistryGeneration").isTextual()
                || !generation.equals(input.path("expectedRegistryGeneration").textValue())) throw failure("REGISTRY_GENERATION_CHANGED");
        if (!input.path("dimension").isTextual() || !input.path("dimension").equals(context.path("dimension"))) throw failure("CONTEXT_SCOPE_MISMATCH");
        NativeBlocks.requireScope(context, input.path("dimension").textValue(), NativeBlocks.position(input.path("position")));
    }

    static ObjectNode profile(String hostDigest, String implementationDigest) {
        ObjectNode profile = ContractJson.newObject().put("format", "mmmm.owned-block-direct-profile/1").put("producerId", PRODUCER)
                .put("hostArtifactDigest", hostDigest).put("implementationDigest", implementationDigest).put("setBlockFlags", 2)
                .put("neighborState", "minecraft:air").put("requireDefaultState", true)
                .put("requireBlockEntityAbsent", true).put("requireFluidEmpty", true);
        profile.putArray("centerStates").add("minecraft:air").add("minecraft:stone"); directFields(profile); return profile;
    }

    static String conditionsDigest(ObjectNode receipt) {
        ObjectNode projection = receipt.deepCopy(); projection.remove(List.of("observedFromTick", "observedToTick", "conditionsDigest"));
        return ContractJson.digest(projection);
    }

    static void directFields(ObjectNode result) {
        result.put("directCoverage", "block_state_cells").put("indirectEffects", "not_observed")
                .put("exactUndoSupported", false).put("lossCode", LOSS);
        ArrayNode limitations = result.putArray("limitations"); LIMITATIONS.forEach(limitations::add);
    }

    static boolean ownedState(JsonNode state) {
        return state.isObject() && state.size() == 2 && state.path("blockId").isTextual()
                && Set.of("minecraft:air", "minecraft:stone").contains(state.path("blockId").textValue())
                && state.path("properties").isObject() && state.path("properties").isEmpty();
    }
    static net.minecraft.world.level.block.state.BlockState desired(JsonNode state) {
        if (!ownedState(state)) throw failure("OWNED_BLOCK_STATE_UNSUPPORTED");
        return "minecraft:air".equals(state.path("blockId").textValue()) ? Blocks.AIR.defaultBlockState() : Blocks.STONE.defaultBlockState();
    }
    private static ArrayNode position(BlockPos position) {
        return ContractJson.newObject().putArray("position").add(position.getX()).add(position.getY()).add(position.getZ());
    }
    private static void requireDigest(String value) { if (value == null || !value.matches("[0-9a-f]{64}")) throw failure("OWNED_BLOCK_SOURCE_UNAVAILABLE"); }
    private static ContractException failure(String code) { return new ContractException(code, "Owned direct block observation is unavailable or changed"); }
}
