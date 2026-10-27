package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import net.minecraft.core.BlockPos;
import net.minecraft.core.Direction;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.phys.shapes.CollisionContext;

/** Native observation only. Rust owns geometry resources and ShapeResult construction. */
final class NativeShapes {
    record Observation(ObjectNode raw, ObjectNode blockState, String neighborDigest, String fluidDigest,
                       boolean loaded, java.util.List<BlockPos> dependencies, long fromTick, long toTick) { }
    private NativeShapes() { }
    static Observation observe(LoadedChunks chunks, ServerLevel level, ObjectNode context, ObjectNode query, boolean shape) {
        if (!query.path("entityContextHandle").isNull()) {
            throw new ContractException("UNSUPPORTED", "Native entity shape context requires an installed scoped entity resolver");
        }
        BlockPos position = NativeBlocks.position(query.path("position"));
        NativeBlocks.requireScope(context, query.path("dimension").asText(), position);
        long from = Integer.toUnsignedLong(level.getServer().getTickCount());
        LoadedBlockView view = new LoadedBlockView(chunks, level, context);
        ObjectNode raw = ContractJson.newObject().put("format", "mmmm.native.voxel-aabbs/1")
                .put("shapeKind", query.path("shapeKind").asText()).put("space", "node_local").put("unit", "blocks")
                .put("provenance", "observed").put("status", "unknown").put("exactness", "unknown").putNull("boxes").putNull("reason");
        ObjectNode actual = null; String neighbor = null; String fluid = null; boolean loaded = false;
        try {
            var state = view.getBlockState(position); actual = NativeBlocks.state(state);
            for (Direction direction : Direction.values()) {
                int x = Math.addExact(position.getX(), direction.getStepX());
                int y = Math.addExact(position.getY(), direction.getStepY());
                int z = Math.addExact(position.getZ(), direction.getStepZ());
                view.getBlockState(new BlockPos(x, y, z));
            }
            neighbor = view.digest(); fluid = view.fluidDigest(position); loaded = true;
            if (shape && (!actual.equals(query.path("blockState")) || !neighbor.equals(query.path("neighborContextDigest").asText()))) {
                throw new ContractException("TARGET_DRIFT", "Actual state or neighbor context differs from the pinned shape query");
            }
            if (shape) {
                String kind = query.path("shapeKind").asText();
                if (!"collision".equals(kind) && !"outline".equals(kind)) {
                    raw.put("status", "unsupported").put("reason", "Native support/fluid shape semantics are not implemented for this target");
                } else {
                    var voxel = "collision".equals(kind) ? state.getCollisionShape(view, position, CollisionContext.empty())
                            : state.getShape(view, position, CollisionContext.empty());
                    var boxes = raw.putArray("boxes");
                    voxel.forAllBoxes((minX, minY, minZ, maxX, maxY, maxZ) -> {
                        if (boxes.size() >= 4096) throw new ContractException("SHAPE_LIMIT", "Native voxel box count exceeds its limit");
                        double[] numbers = {minX, minY, minZ, maxX, maxY, maxZ};
                        for (double number : numbers) if (!Double.isFinite(number)) throw new ContractException("SHAPE_INVALID", "Native shape has a non-finite bound");
                        if (minX > maxX || minY > maxY || minZ > maxZ) throw new ContractException("SHAPE_INVALID", "Native shape has an inverted bound");
                        boxes.addArray().add(minX).add(minY).add(minZ).add(maxX).add(maxY).add(maxZ);
                    });
                    raw.put("status", "known").put("exactness", "exact");
                    if (ContractJson.bytes(raw).length > 256 * 1024) throw new ContractException("SHAPE_LIMIT", "Native shape observation exceeds its byte limit");
                }
            }
        } catch (ArithmeticException exception) {
            raw.put("reason", "Neighbor coordinate exceeds the native int32 position range"); loaded = false;
        } catch (ContractException exception) {
            if (!"CHUNK_NOT_LOADED".equals(exception.code())) throw exception;
            raw.put("reason", "A required loaded-only native dependency is unavailable").put("status", "unknown").put("exactness", "unknown").putNull("boxes");
            loaded = false;
        }
        return new Observation(raw, actual, neighbor, fluid, loaded, view.dependencies(), from,
                Integer.toUnsignedLong(level.getServer().getTickCount()));
    }
}
