package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.sdk.ContractException;
import net.minecraft.core.BlockPos;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.FullChunkStatus;
import net.minecraft.world.level.ChunkPos;
import net.minecraft.world.level.chunk.LevelChunk;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;

/** Lifecycle-observed chunks only. This class never calls getChunk or generates a chunk. */
final class LoadedChunks {
    private final Map<ServerLevel, Map<Long, LevelChunk>> levels = new IdentityHashMap<>();
    synchronized void loaded(ServerLevel level, LevelChunk chunk) {
        levels.computeIfAbsent(level, ignored -> new HashMap<>()).put(chunk.getPos().pack(), chunk);
    }
    synchronized void unloaded(ServerLevel level, LevelChunk chunk) {
        Map<Long, LevelChunk> chunks = levels.get(level);
        if (chunks != null) { chunks.remove(chunk.getPos().pack(), chunk); if (chunks.isEmpty()) levels.remove(level); }
    }
    synchronized LevelChunk require(ServerLevel level, BlockPos position) {
        if (!level.getServer().isSameThread()) throw new ContractException("WRONG_THREAD", "Loaded chunk access requires the server thread");
        long minY = level.getMinY(); long maxY = minY + level.getHeight();
        if (position.getY() < minY || position.getY() >= maxY) {
            throw new ContractException("TARGET_OUT_OF_WORLD", "Requested block is outside the actual level height");
        }
        LevelChunk chunk = levels.getOrDefault(level, Map.of()).get(ChunkPos.pack(position.getX() >> 4, position.getZ() >> 4));
        if (chunk == null || !chunk.getFullStatus().isOrAfter(FullChunkStatus.FULL)) {
            throw new ContractException("CHUNK_NOT_LOADED", "Requested chunk is not currently accessible in the loaded level");
        }
        return chunk;
    }
    synchronized void clear() { levels.clear(); }
}
