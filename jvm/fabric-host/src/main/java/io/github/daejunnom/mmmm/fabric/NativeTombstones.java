package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import net.minecraft.core.BlockPos;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.EntityType;

/**
 * Private dispatch history for one actually observed entity instance. This is
 * neither persistent UUID membership nor proof of a successful command return.
 */
final class NativeTombstones {
    private static final int MAX_RECORDS = 512;
    private static final int MAX_CONTEXT_BYTES = 16 * 1024;
    private final LoadedChunks chunks;
    private final LoadedEntities entities;
    private final Map<Key, Record> records = new HashMap<>();
    private MinecraftServer owner;

    NativeTombstones(LoadedChunks chunks, LoadedEntities entities) {
        this.chunks = Objects.requireNonNull(chunks);
        this.entities = Objects.requireNonNull(entities);
    }

    /**
     * Composition calls this only inside the exact guarded kill delegate, after
     * LocalContext.beginMutation and immediately before native dispatch. Native
     * failure or response loss leaves the attempt recorded; neither is success.
     */
    synchronized void recordDispatchAttempt(Invocation sourceInvocation, ObjectNode installedContext,
                                            ServerLevel actualLevel, Entity actualOwnedEntity,
                                            String actualBeforeSha256, String trustedOwnerTag) {
        requireThread(actualLevel);
        Objects.requireNonNull(sourceInvocation); Objects.requireNonNull(actualOwnedEntity);
        ObjectNode context = checkedContext(sourceInvocation, installedContext, actualLevel);
        if (actualBeforeSha256 == null || !actualBeforeSha256.matches("[a-f0-9]{64}")) throw invalid();
        String actualType = BuiltInRegistries.ENTITY_TYPE.getKey(actualOwnedEntity.getType()).toString();
        UUID uuid = actualOwnedEntity.getUUID();
        if (NativeTargets.requireOwnedEntity(chunks, entities, actualLevel, context, uuid, actualType, trustedOwnerTag) != actualOwnedEntity) throw invalid();
        Key key = new Key(ContractJson.digest(sourceInvocation.wire()), uuid);
        // One immutable witness per original invocation/UUID. Replacing an old
        // witness would permit a later instance to inherit an earlier receipt.
        if (records.containsKey(key)) throw new ContractException("NATIVE_HISTORY_CONFLICT", "The original dispatch already owns an entity witness");
        if (records.size() >= MAX_RECORDS) throw new ContractException("NATIVE_HISTORY_LIMIT", "Native destruction history has reached its finite capacity");
        BlockPos position = actualOwnedEntity.blockPosition();
        Record record = new Record(context, actualLevel, actualOwnedEntity, actualOwnedEntity.getType(), uuid,
                actualType, new BlockPos(position.getX(), position.getY(), position.getZ()), actualOwnedEntity.position().x,
                actualOwnedEntity.position().y, actualOwnedEntity.position().z, actualBeforeSha256, trustedOwnerTag,
                sourceInvocation.invocationId(), sourceInvocation.bindingId(), sourceInvocation.operationId());
        records.put(key, record);
    }

    /** Any later load of this UUID invalidates every older witness, including reload of the same object. */
    synchronized void loaded(Entity actualEntity, ServerLevel actualLevel) {
        requireThread(actualLevel); Objects.requireNonNull(actualEntity);
        UUID uuid = actualEntity.getUUID();
        for (Record record : records.values()) if (record.uuid.equals(uuid)) record.invalidated = true;
    }

    /** The expected source is a retained host Invocation, never reconstructed from an inspector payload. */
    synchronized ObjectNode destroyed(Invocation originalInvocation, ServerLevel actualLevel,
                                      ObjectNode installedContext, ObjectNode exactSelector) {
        requireThread(actualLevel); Objects.requireNonNull(originalInvocation); Objects.requireNonNull(exactSelector);
        ObjectNode context = checkedContext(originalInvocation, installedContext, actualLevel);
        if (!"entity".equals(exactSelector.path("kind").asText()) || exactSelector.size() != 4
                || !actualLevel.dimension().identifier().toString().equals(exactSelector.path("dimension").asText())) throw invalid();
        UUID uuid;
        try { uuid = UUID.fromString(exactSelector.path("uuid").asText()); }
        catch (IllegalArgumentException exception) { throw invalid(); }
        if (!uuid.toString().equals(exactSelector.path("uuid").asText())) throw invalid();
        Record record = records.get(new Key(ContractJson.digest(originalInvocation.wire()), uuid));
        if (record == null || record.invalidated) return null;
        if (!record.context.equals(context) || record.level != actualLevel
                || !record.typeId.equals(exactSelector.path("expectedType").asText())) throw invalid();
        // A retained object is an exact native identity. No storage scan or
        // global UUID-absence claim is introduced when its event membership ends.
        Entity actual = record.entity;
        if (actual.level() != record.level || !record.uuid.equals(actual.getUUID()) || actual.getType() != record.type
                || !record.typeId.equals(BuiltInRegistries.ENTITY_TYPE.getKey(actual.getType()).toString())
                || !actual.entityTags().contains(record.ownerTag) || !record.position.equals(actual.blockPosition())
                || Double.doubleToRawLongBits(record.x) != Double.doubleToRawLongBits(actual.position().x)
                || Double.doubleToRawLongBits(record.y) != Double.doubleToRawLongBits(actual.position().y)
                || Double.doubleToRawLongBits(record.z) != Double.doubleToRawLongBits(actual.position().z)) return null;
        NativeBlocks.requireScope(context, actualLevel.dimension().identifier().toString(), record.position);
        chunks.require(actualLevel, record.position);
        Entity replacement;
        try { replacement = entities.lookup(actualLevel, uuid); }
        catch (ContractException exception) {
            // During a native remove callback the old identity may still be in
            // the event index. It remains unknown until membership has ended.
            if ("ENTITY_TARGET_NOT_ACTIVE".equals(exception.code())) return null;
            throw exception;
        }
        if (replacement != null) {
            if (replacement != actual) record.invalidated = true;
            return null;
        }
        Entity.RemovalReason reason = actual.getRemovalReason();
        if (!actual.isRemoved() || reason == null || !reason.shouldDestroy() || reason.shouldSave()) return null;
        return ContractJson.newObject().put("sourceInvocationId", record.invocationId).put("sourceBindingId", record.bindingId)
                .put("sourceOperationId", record.operationId).put("beforeSha256", record.beforeSha256)
                .put("entityUuid", record.uuid.toString()).put("entityType", record.typeId).put("ownerTag", record.ownerTag)
                .put("removalReason", reason.name()).put("membershipClaim", "original_observed_instance_destroyed");
    }

    /** Clear at actual stop or authority-generation invalidation; live LoadedEntities is separate. */
    synchronized void clear() {
        if (owner != null && !owner.isSameThread()) throw new ContractException("WRONG_THREAD", "Native destruction history requires the server thread");
        records.clear(); owner = null;
    }

    private ObjectNode checkedContext(Invocation invocation, ObjectNode installed, ServerLevel level) {
        Objects.requireNonNull(installed);
        if (ContractJson.bytes(installed).length > MAX_CONTEXT_BYTES || !installed.equals(invocation.context())
                || !invocation.contextDigest().equals(installed.path("contextDigest").asText())
                || !level.dimension().identifier().toString().equals(installed.path("dimension").asText())) throw invalid();
        return installed.deepCopy();
    }
    private void requireThread(ServerLevel level) {
        Objects.requireNonNull(level); MinecraftServer server = level.getServer();
        if (!server.isSameThread()) throw new ContractException("WRONG_THREAD", "Native destruction history requires the server thread");
        if (owner == null) owner = server;
        if (owner != server) throw new ContractException("NATIVE_HISTORY_CONTEXT_MISMATCH", "Native destruction histories cannot combine actual server generations");
    }
    private static ContractException invalid() { return new ContractException("NATIVE_HISTORY_CONTEXT_MISMATCH", "Native destruction history differs from its retained source and actual target"); }
    private record Key(String sourceDigest, UUID uuid) { }
    private static final class Record {
        private final ObjectNode context;
        private final ServerLevel level;
        private final Entity entity;
        private final EntityType<?> type;
        private final UUID uuid;
        private final String typeId;
        private final BlockPos position;
        private final double x, y, z;
        private final String beforeSha256, ownerTag, invocationId, bindingId, operationId;
        private boolean invalidated;
        private Record(ObjectNode context, ServerLevel level, Entity entity, EntityType<?> type, UUID uuid, String typeId,
                       BlockPos position, double x, double y, double z, String beforeSha256, String ownerTag,
                       String invocationId, String bindingId, String operationId) {
            this.context = context.deepCopy(); this.level = level; this.entity = entity; this.type = type; this.uuid = uuid;
            this.typeId = typeId; this.position = position; this.x = x; this.y = y; this.z = z;
            this.beforeSha256 = beforeSha256; this.ownerTag = ownerTag; this.invocationId = invocationId;
            this.bindingId = bindingId; this.operationId = operationId;
        }
    }
}
