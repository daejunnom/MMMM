package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import net.minecraft.core.BlockPos;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.block.Block;
import net.minecraft.world.level.block.state.BlockState;
import net.minecraft.world.level.block.state.properties.Property;
import java.util.HashSet;
import java.util.Set;

/** Platform registry codecs and direct block observations; no geometry or project transformations. */
final class NativeBlocks {
    private NativeBlocks() { }
    static BlockPos position(JsonNode value) {
        if (!value.isArray() || value.size() != 3) throw new ContractException("POSITION_INVALID", "Expected three block coordinates");
        for (JsonNode coordinate : value) {
            try { if (!coordinate.isNumber()) throw new ArithmeticException(); coordinate.decimalValue().intValueExact(); }
            catch (ArithmeticException exception) { throw new ContractException("POSITION_INVALID", "Block coordinates must be int32 values"); }
        }
        return new BlockPos(value.get(0).intValue(), value.get(1).intValue(), value.get(2).intValue());
    }
    static ObjectNode observe(LoadedChunks chunks, ServerLevel level, BlockPos position) {
        // Readback follows the native state values; it never reconstructs state from the requested desired value.
        BlockState actual = chunks.require(level, position).getBlockState(position);
        ObjectNode result = ContractJson.newObject().put("dimension", level.dimension().identifier().toString())
                .put("observedTick", Long.toString(Integer.toUnsignedLong(level.getServer().getTickCount())));
        result.putArray("position").add(position.getX()).add(position.getY()).add(position.getZ());
        result.set("blockState", state(actual));
        return result;
    }
    static ObjectNode state(BlockState state) {
        ObjectNode result = ContractJson.newObject().put("blockId", BuiltInRegistries.BLOCK.getKey(state.getBlock()).toString());
        ObjectNode properties = result.putObject("properties");
        for (Property<?> property : state.getProperties()) writeProperty(properties, state, property);
        return result;
    }
    private static <T extends Comparable<T>> void writeProperty(ObjectNode output, BlockState state, Property<T> property) {
        output.put(property.getName(), property.getName(state.getValue(property)));
    }
    static BlockState decode(JsonNode value) {
        ObjectNode input = ContractJson.object(value);
        if (input.size() != 2 || !input.path("blockId").isTextual() || !input.path("properties").isObject()) {
            throw new ContractException("BLOCK_STATE_INVALID", "Expected a complete block ID and property object");
        }
        Block found = null;
        int scanned = 0;
        for (Block block : BuiltInRegistries.BLOCK) {
            if (++scanned > 100_000) throw new ContractException("REGISTRY_LIMIT", "Block registry exceeds the query limit");
            if (BuiltInRegistries.BLOCK.getKey(block).toString().equals(input.path("blockId").asText())) { found = block; break; }
        }
        if (found == null) throw new ContractException("BLOCK_UNKNOWN", "Requested block is not present in the live registry");
        BlockState result = found.defaultBlockState();
        Set<String> expected = new HashSet<>();
        for (Property<?> property : result.getProperties()) expected.add(property.getName());
        Set<String> supplied = new HashSet<>(); input.path("properties").fieldNames().forEachRemaining(supplied::add);
        if (!expected.equals(supplied)) throw new ContractException("BLOCK_PROPERTY_MISMATCH", "All native block properties must be supplied exactly");
        for (Property<?> property : result.getProperties()) result = setProperty(result, property, input.path("properties").get(property.getName()));
        return result;
    }
    private static <T extends Comparable<T>> BlockState setProperty(BlockState state, Property<T> property, JsonNode value) {
        if (value == null || !value.isTextual()) throw new ContractException("BLOCK_PROPERTY_INVALID", "Block property values must be text");
        T parsed = property.getValue(value.asText()).orElseThrow(() -> new ContractException("BLOCK_PROPERTY_INVALID", "Block property value is not in the native enum"));
        return state.setValue(property, parsed);
    }
    static void requireScope(ObjectNode context, String dimension, BlockPos position) {
        for (JsonNode region : context.path("scope").path("regions")) {
            if (!dimension.equals(region.path("dimension").asText())
                    || !context.path("contextId").asText().equals(region.path("contextId").asText())
                    || !context.path("environment").path("worldId").asText().equals(region.path("worldId").asText())) continue;
            JsonNode min = region.path("min"), max = region.path("maxExclusive");
            int[] coordinates = {position.getX(), position.getY(), position.getZ()};
            boolean included = true;
            for (int axis = 0; axis < 3; axis++) {
                included &= min.get(axis).bigIntegerValue().compareTo(java.math.BigInteger.valueOf(coordinates[axis])) <= 0
                        && max.get(axis).bigIntegerValue().compareTo(java.math.BigInteger.valueOf(coordinates[axis])) > 0;
            }
            if (included) return;
        }
        throw new ContractException("SCOPE_DENIED", "Block position is outside the paired context's explicit region");
    }
}
