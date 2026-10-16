package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.EntityType;

/**
 * Server-generation entity membership observed through load and unload events.
 * This index never loads an entity or looks up persistent entity storage. A null
 * lookup means only that no matching loaded entity was observed in this generation.
 */
final class LoadedEntities {
    private static final int MAX_ENTITIES = 65_536;

    private final Map<Entity, Entry> identities = new IdentityHashMap<>();
    private final Map<UUID, Map<Entity, Entry>> uuids = new HashMap<>();
    private MinecraftServer owner;
    private boolean poisoned;

    synchronized void loaded(Entity entity, ServerLevel level) {
        Objects.requireNonNull(entity, "entity");
        requireThread(level);
        if (poisoned) return;

        UUID uuid = entity.getUUID();
        EntityType<?> type = entity.getType();
        if (uuid == null || type == null || entity.level() != level || entity.isRemoved()) {
            poisoned = true;
            return;
        }

        Entry existing = identities.get(entity);
        if (existing != null) {
            if (!existing.uuid().equals(uuid) || existing.level() != level || existing.type() != type) {
                poisoned = true;
            }
            return;
        }
        if (identities.size() >= MAX_ENTITIES) {
            // Preserve every already observed identity. Eviction would turn an
            // incomplete index into a false absence or hide a UUID collision.
            poisoned = true;
            return;
        }

        Entry entry = new Entry(entity, level, uuid, type);
        identities.put(entity, entry);
        uuids.computeIfAbsent(uuid, ignored -> new IdentityHashMap<>()).put(entity, entry);
    }

    synchronized void unloaded(Entity entity, ServerLevel level) {
        Objects.requireNonNull(entity, "entity");
        requireThread(level);
        Entry entry = identities.get(entity);
        if (entry == null) return;
        if (entry.level() != level) {
            poisoned = true;
            return;
        }
        // Removal can already be flagged by the unload event. Remove by the
        // recorded object identity and UUID rather than asking storage for it.
        if (!entry.uuid().equals(entity.getUUID()) || entry.type() != entity.getType()) {
            poisoned = true;
        }
        identities.remove(entity);
        Map<Entity, Entry> matches = uuids.get(entry.uuid());
        if (matches == null || matches.remove(entity) != entry) {
            poisoned = true;
            return;
        }
        if (matches.isEmpty()) uuids.remove(entry.uuid());
    }

    synchronized Entity lookup(ServerLevel requestedLevel, UUID uuid) {
        Objects.requireNonNull(uuid, "uuid");
        requireThread(requestedLevel);
        if (poisoned) {
            throw unavailable();
        }
        Map<Entity, Entry> matches = uuids.get(uuid);
        if (matches == null) return null;
        if (matches.size() != 1) {
            throw new ContractException("ENTITY_UUID_COLLISION", "Several loaded entities share the requested UUID");
        }

        Entry entry = matches.values().iterator().next();
        Entity entity = entry.entity();
        if (identities.get(entity) != entry || !entry.uuid().equals(entity.getUUID())
                || entry.type() != entity.getType() || entity.level() != entry.level()) {
            poisoned = true;
            throw unavailable();
        }
        if (entity.isRemoved()) {
            throw new ContractException("ENTITY_TARGET_NOT_ACTIVE", "The observed entity is being removed");
        }
        if (entry.level() != requestedLevel) {
            throw new ContractException("TARGET_WRONG_DIMENSION", "The loaded entity belongs to another actual level");
        }
        return entity;
    }

    /** Clear only at the actual server-generation boundary, never on grant rotation. */
    synchronized void clear() {
        if (owner != null && !owner.isSameThread()) {
            throw new ContractException("WRONG_THREAD", "Loaded entity access requires the server thread");
        }
        identities.clear();
        uuids.clear();
        owner = null;
        poisoned = false;
    }

    private void requireThread(ServerLevel level) {
        Objects.requireNonNull(level, "level");
        MinecraftServer server = level.getServer();
        if (!server.isSameThread()) {
            throw new ContractException("WRONG_THREAD", "Loaded entity access requires the server thread");
        }
        if (owner == null) owner = server;
        if (owner != server) {
            throw new ContractException("ENTITY_INDEX_UNAVAILABLE", "Loaded entity generations cannot be combined");
        }
    }

    private static ContractException unavailable() {
        return new ContractException("ENTITY_INDEX_UNAVAILABLE", "Loaded entity membership is incomplete for this generation");
    }

    private record Entry(Entity entity, ServerLevel level, UUID uuid, EntityType<?> type) {}
}
