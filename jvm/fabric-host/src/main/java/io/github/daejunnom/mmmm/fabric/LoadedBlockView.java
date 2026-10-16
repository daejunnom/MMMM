package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import net.minecraft.core.BlockPos;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.BlockGetter;
import net.minecraft.world.level.block.entity.BlockEntity;
import net.minecraft.world.level.block.state.BlockState;
import net.minecraft.world.level.material.FluidState;
import java.util.LinkedHashMap;
import java.util.Map;

/** Every native shape getter read is authorized and backed by an already observed loaded chunk. */
final class LoadedBlockView implements BlockGetter {
    private final LoadedChunks chunks;
    private final ServerLevel level;
    private final ObjectNode context;
    private final Map<BlockPos, ObjectNode> observations = new LinkedHashMap<>();
    private int accesses;
    LoadedBlockView(LoadedChunks chunks, ServerLevel level, ObjectNode context) {
        this.chunks = chunks; this.level = level; this.context = context.deepCopy();
    }
    private BlockState state(BlockPos position) {
        if (++accesses > 1024 || observations.size() >= 256 && !observations.containsKey(position)) {
            throw new ContractException("SHAPE_DEPENDENCY_LIMIT", "Native shape reads exceed their dependency limit");
        }
        NativeBlocks.requireScope(context, level.dimension().identifier().toString(), position);
        BlockState state = chunks.require(level, position).getBlockState(position);
        BlockPos immutable = position.immutable();
        observations.putIfAbsent(immutable, NativeBlocks.state(state));
        return state;
    }
    @Override public BlockState getBlockState(BlockPos position) { return state(position); }
    @Override public FluidState getFluidState(BlockPos position) { return state(position).getFluidState(); }
    @Override public BlockEntity getBlockEntity(BlockPos position) {
        state(position);
        // getBlockEntity's default creation policy may mutate; read only the already existing native map.
        return chunks.require(level, position).getBlockEntities().get(position);
    }
    @Override public int getHeight() { return level.getHeight(); }
    @Override public int getMinY() { return level.getMinY(); }
    String digest() {
        var records = ContractJson.newObject().putArray("states");
        observations.entrySet().stream().sorted(java.util.Comparator
                .comparingInt((Map.Entry<BlockPos, ObjectNode> value) -> value.getKey().getX())
                .thenComparingInt(value -> value.getKey().getY()).thenComparingInt(value -> value.getKey().getZ()))
                .forEach(entry -> {
                    ObjectNode record = ContractJson.newObject();
                    record.putArray("position").add(entry.getKey().getX()).add(entry.getKey().getY()).add(entry.getKey().getZ());
                    record.set("blockState", entry.getValue().deepCopy()); records.add(record);
                });
        return ContractJson.digest(records);
    }
    String fluidDigest(BlockPos position) {
        FluidState fluid = getFluidState(position);
        return ContractJson.digest(ContractJson.newObject().put("fluidId", BuiltInRegistries.FLUID.getKey(fluid.getType()).toString())
                .put("amount", fluid.getAmount()).put("source", fluid.isSource()));
    }
    java.util.List<BlockPos> dependencies() { return java.util.List.copyOf(observations.keySet()); }
}
