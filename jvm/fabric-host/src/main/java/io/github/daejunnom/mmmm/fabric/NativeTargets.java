package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.fabric.mixin.ScoreboardReadAccess;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import net.minecraft.core.BlockPos;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.CollectionTag;
import net.minecraft.nbt.ListTag;
import net.minecraft.nbt.NbtIo;
import net.minecraft.nbt.StringTag;
import net.minecraft.nbt.Tag;
import net.minecraft.world.level.storage.CommandStorage;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.util.ProblemReporter;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.level.block.entity.BlockEntity;
import net.minecraft.world.level.storage.TagValueOutput;
import net.minecraft.world.scores.Objective;
import net.minecraft.world.scores.DisplaySlot;
import net.minecraft.world.scores.ReadOnlyScoreInfo;
import net.minecraft.world.scores.Score;
import net.minecraft.world.scores.Scoreboard;
import net.minecraft.world.scores.ScoreHolder;

/** Independent native observations. This class neither compiles instructions nor creates target state. */
final class NativeTargets {
    private static final int MAX_SELECTOR_BYTES = 16 * 1024;
    private static final int MAX_NATIVE_BYTES = 64 * 1024;
    private static final int MAX_RAW_BYTES = 256 * 1024;
    private static final int MAX_TAGS = 128;
    private static final int MAX_TAG_BYTES = 16 * 1024;
    private static final int MAX_NBT_DEPTH = 64;
    private static final int MAX_NBT_NODES = 16_384;
    private static final int MAX_NBT_CONTAINER_ENTRIES = 4096;
    private static final int MAX_SCORE_HOLDERS = 4096;
    private static final int MAX_DISPLAY_SLOTS = 32;
    private static final Set<String> NATIVE_LEAF_CLASSES = Set.of("net.minecraft.nbt.ByteTag", "net.minecraft.nbt.ShortTag",
            "net.minecraft.nbt.IntTag", "net.minecraft.nbt.LongTag", "net.minecraft.nbt.FloatTag", "net.minecraft.nbt.DoubleTag",
            "net.minecraft.nbt.ByteArrayTag", "net.minecraft.nbt.IntArrayTag", "net.minecraft.nbt.LongArrayTag",
            "net.minecraft.nbt.StringTag", "net.minecraft.nbt.EndTag");
    private NativeTargets() { }

    /** Trusted composition must check an approved exact resource-to-native-target mapping. */
    @FunctionalInterface
    interface ResourceAuthority {
        void require(ObjectNode installedContext, ObjectNode exactSelector);
        default CommandStorage commandStorage(ServerLevel level) { return null; }
    }

    /** Trusted history is bound to the retained original invocation and owner route by composition. */
    @FunctionalInterface
    interface EntityHistory {
        ObjectNode destroyed(ServerLevel actualLevel, ObjectNode installedContext, ObjectNode exactSelector);
    }

    static Observation observe(LoadedChunks chunks, LoadedEntities entities, ServerLevel level,
                               ObjectNode installedContext, ObjectNode target) {
        return observe(chunks, entities, level, installedContext, target, (context, selector) -> {
            throw new ContractException("SCOPE_DENIED", "Native resource observations require an approved exact target mapping");
        });
    }

    static Observation observe(LoadedChunks chunks, LoadedEntities entities, ServerLevel level,
                               ObjectNode installedContext, ObjectNode target, ResourceAuthority resources) {
        return observe(chunks, entities, level, installedContext, target, resources, (actualLevel, context, selector) -> null);
    }

    static Observation observe(LoadedChunks chunks, LoadedEntities entities, ServerLevel level,
                               ObjectNode installedContext, ObjectNode target, ResourceAuthority resources,
                               EntityHistory history) {
        Objects.requireNonNull(chunks); Objects.requireNonNull(entities); Objects.requireNonNull(resources);
        Objects.requireNonNull(history);
        requireThread(level);
        ObjectNode context = installedContext.deepCopy(); ObjectNode selector = target.deepCopy();
        if (ContractJson.bytes(selector).length > MAX_SELECTOR_BYTES) throw limit();
        String kind = text(selector, "kind");
        validateSelector(selector, kind);
        requireLevel(level, context);
        if (selector.has("dimension") && !text(selector, "dimension").equals(level.dimension().identifier().toString())) {
            throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Native target selector differs from the actual observation level");
        }
        long fromTick = Integer.toUnsignedLong(level.getServer().getTickCount());
        ObjectNode raw = base(selector);
        switch (kind) {
            case "block_state" -> blockState(chunks, level, context, selector, raw);
            case "block_entity" -> blockEntity(chunks, level, context, selector, raw);
            case "entity" -> entity(chunks, entities, level, context, selector, raw, history);
            case "storage" -> {
                requireResource(context, selector, resources);
                storage(level, selector, raw, resources.commandStorage(level));
            }
            case "score" -> {
                requireResource(context, selector, resources);
                score(level, selector, raw);
            }
            case "objective" -> {
                requireResource(context, selector, resources);
                objective(level, selector, raw);
            }
            default -> throw invalid();
        }
        requireThread(level); requireLevel(level, context);
        byte[] bytes = ContractJson.canonical(raw);
        if (bytes.length > MAX_RAW_BYTES) throw limit();
        return new Observation(raw, bytes, fromTick, Integer.toUnsignedLong(level.getServer().getTickCount()));
    }

    /** Executor guard: returns only an actually observed, loaded, scoped entity of the exact native type. */
    static Entity requireEntity(LoadedChunks chunks, LoadedEntities entities, ServerLevel level,
                                ObjectNode context, UUID uuid, String expectedType) {
        requireThread(level); requireLevel(level, context);
        Entity actual = entities.lookup(level, uuid);
        if (actual == null) throw new ContractException("ENTITY_NOT_OBSERVED", "The requested loaded entity has not been observed");
        var actualPosition = actual.position();
        double[] components = {actualPosition.x, actualPosition.y, actualPosition.z};
        for (double component : components) if (!Double.isFinite(component)
                || component < Integer.MIN_VALUE || component >= (double) Integer.MAX_VALUE + 1.0) {
            throw new ContractException("TARGET_OUT_OF_WORLD", "Actual entity position cannot be represented by a native block position");
        }
        BlockPos position = actual.blockPosition();
        if (position.getX() != (int) Math.floor(components[0]) || position.getY() != (int) Math.floor(components[1])
                || position.getZ() != (int) Math.floor(components[2])) {
            throw new ContractException("TARGET_IDENTITY_MISMATCH", "Actual entity position differs from its native block position");
        }
        NativeBlocks.requireScope(context, level.dimension().identifier().toString(), position);
        chunks.require(level, position);
        if (actual.level() != level || actual.isRemoved() || !uuid.equals(actual.getUUID())) {
            throw new ContractException("TARGET_IDENTITY_MISMATCH", "The actual entity identity differs from its observed membership");
        }
        String actualType = BuiltInRegistries.ENTITY_TYPE.getKey(actual.getType()).toString();
        if (!actualType.equals(expectedType)) throw new ContractException("TARGET_IDENTITY_MISMATCH", "The actual entity type differs from its approved target");
        return actual;
    }

    /** Ownership tags are supplied only from the approved retained Rust binding; they are never inferred here. */
    static Entity requireOwnedEntity(LoadedChunks chunks, LoadedEntities entities, ServerLevel level,
                                     ObjectNode context, UUID uuid, String expectedType, String ownershipTag) {
        if (ownershipTag == null || ownershipTag.isEmpty() || ownershipTag.length() > 128) throw invalid();
        Entity actual = requireEntity(chunks, entities, level, context, uuid, expectedType);
        if (actual.entityTags().size() > MAX_TAGS || !actual.entityTags().contains(ownershipTag)
                || actual.isPassenger() || actual.isVehicle()) {
            throw new ContractException("TARGET_OWNERSHIP_MISMATCH", "The actual native entity does not satisfy the approved ownership binding");
        }
        return actual;
    }

    static BlockEntity requireBlockEntity(LoadedChunks chunks, ServerLevel level, ObjectNode context,
                                          ObjectNode selector, String expectedType) {
        BlockPos position = requirePosition(chunks, level, context, selector);
        var chunk = chunks.require(level, position); var state = chunk.getBlockState(position);
        BlockEntity actual = chunk.getBlockEntities().get(position);
        if (actual == null || !state.hasBlockEntity() || actual.isRemoved() || actual.getLevel() != level
                || !position.equals(actual.getBlockPos()) || !state.equals(actual.getBlockState())
                || !BuiltInRegistries.BLOCK_ENTITY_TYPE.getKey(actual.getType()).toString().equals(expectedType)) {
            throw new ContractException("TARGET_IDENTITY_MISMATCH", "The existing block entity does not match the approved native target");
        }
        return actual;
    }

    private static void blockState(LoadedChunks chunks, ServerLevel level, ObjectNode context,
                                    ObjectNode selector, ObjectNode raw) {
        BlockPos position = requirePosition(chunks, level, context, selector);
        var actual = chunks.require(level, position).getBlockState(position);
        ObjectNode payload = ContractJson.newObject(); payload.set("blockState", NativeBlocks.state(actual));
        payload.put("hasBlockEntity", actual.hasBlockEntity());
        known(raw, "present", "loaded_block_position", "native_block_state",
                actual.hasBlockEntity() ? "tracked_changes_only" : "full_target", payload);
        if (actual.hasBlockEntity()) raw.put("reason", "native_block_entity_payload_requires_separate_full_capture");
    }

    private static void blockEntity(LoadedChunks chunks, ServerLevel level, ObjectNode context,
                                     ObjectNode selector, ObjectNode raw) {
        BlockPos position = requirePosition(chunks, level, context, selector);
        var chunk = chunks.require(level, position); var state = chunk.getBlockState(position);
        BlockEntity actual = chunk.getBlockEntities().get(position);
        if (actual == null) {
            if (state.hasBlockEntity()) {
                unknown(raw, "native_block_entity_not_initialized", "native_persisted_block_entity");
            } else {
                ObjectNode payload = ContractJson.newObject(); payload.set("blockState", NativeBlocks.state(state));
                known(raw, "absent", "loaded_block_position", "native_persisted_block_entity", "full_target", payload);
            }
            return;
        }
        if (!state.hasBlockEntity() || actual.isRemoved() || actual.getLevel() != level
                || !position.equals(actual.getBlockPos()) || !state.equals(actual.getBlockState())) {
            throw new ContractException("TARGET_IDENTITY_MISMATCH", "The existing block entity differs from the actual loaded block");
        }
        ObjectNode payload = ContractJson.newObject(); payload.set("blockState", NativeBlocks.state(state));
        payload.put("blockEntityType", BuiltInRegistries.BLOCK_ENTITY_TYPE.getKey(actual.getType()).toString());
        try { payload.set("nativeNbt", serialize(level, actual::saveWithFullMetadata)); }
        catch (ContractException exception) {
            if (!"NATIVE_SERIALIZATION_INCOMPLETE".equals(exception.code())) throw exception;
            unknown(raw, "native_block_entity_codec_incomplete", "native_persisted_block_entity"); return;
        }
        requirePosition(chunks, level, context, selector);
        if (chunk.getBlockEntities().get(position) != actual || !chunk.getBlockState(position).equals(state)
                || actual.isRemoved() || actual.getLevel() != level) {
            throw new ContractException("TARGET_DRIFT", "Block entity changed during native serialization");
        }
        known(raw, "present", "loaded_block_position", "native_persisted_block_entity", "full_target", payload);
    }

    private static void entity(LoadedChunks chunks, LoadedEntities entities, ServerLevel level,
                                ObjectNode context, ObjectNode selector, ObjectNode raw, EntityHistory history) {
        UUID uuid = uuid(text(selector, "uuid"));
        if (entities.lookup(level, uuid) == null) {
            ObjectNode destroyed = history.destroyed(level, context.deepCopy(), selector.deepCopy());
            if (destroyed != null) {
                known(raw, "absent", "retained_destroyed_native_identity", "observed_entity_instance", "full_target", destroyed.deepCopy());
                return;
            }
            // Neither loaded chunk coverage nor a loaded entity index proves persistent global UUID absence.
            unknown(raw, "loaded_uuid_not_observed", "native_persisted_entity"); return;
        }
        Entity actual = requireEntity(chunks, entities, level, context, uuid, text(selector, "expectedType"));
        if (actual.isVehicle() || actual.isPassenger()) {
            unknown(raw, "native_entity_mount_footprint_not_observed", "native_persisted_entity"); return;
        }
        ObjectNode payload = ContractJson.newObject().put("entityType", BuiltInRegistries.ENTITY_TYPE.getKey(actual.getType()).toString());
        var position = actual.position();
        for (double component : new double[] {position.x, position.y, position.z}) {
            if (!Double.isFinite(component)) throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Actual entity position is nonfinite");
        }
        payload.putArray("position").add(position.x).add(position.y).add(position.z);
        var tags = payload.putArray("tags"); int[] tagBytes = {0};
        if (actual.entityTags().size() > MAX_TAGS) throw limit();
        actual.entityTags().stream().sorted().forEach(tag -> {
            if (tag.length() > MAX_TAG_BYTES / 3) throw limit();
            tagBytes[0] = Math.addExact(tagBytes[0], tag.getBytes(StandardCharsets.UTF_8).length);
            if (tagBytes[0] > MAX_TAG_BYTES) throw limit(); tags.add(tag);
        });
        boolean[] saved = {false};
        ObjectNode nbt;
        try { nbt = serialize(level, output -> saved[0] = actual.save(output)); }
        catch (ContractException exception) {
            if (!"NATIVE_SERIALIZATION_INCOMPLETE".equals(exception.code())) throw exception;
            unknown(raw, "native_entity_codec_incomplete", "native_persisted_entity"); return;
        }
        if (!saved[0]) { unknown(raw, "native_entity_save_declined", "native_persisted_entity"); return; }
        payload.set("nativeNbt", nbt);
        if (requireEntity(chunks, entities, level, context, uuid, text(selector, "expectedType")) != actual
                || !actual.position().equals(position)) {
            throw new ContractException("TARGET_DRIFT", "Entity changed during native serialization");
        }
        known(raw, "present", "loaded_entity_identity", "native_persisted_entity", "full_target", payload);
    }

    private static void score(ServerLevel level, ObjectNode selector, ObjectNode raw) {
        var scoreboard = level.getScoreboard(); Objective objective = scoreboard.getObjective(text(selector, "objective"));
        if (objective == null) {
            known(raw, "absent", "current_native_scoreboard", "native_score_entry", "full_target", ContractJson.newObject().put("objectivePresent", false)); return;
        }
        if (!text(selector, "objective").equals(objective.getName())) throw new ContractException("TARGET_IDENTITY_MISMATCH", "Native objective name differs from the selected map membership");
        ReadOnlyScoreInfo score = scoreboard.getPlayerScoreInfo(ScoreHolder.forNameOnly(text(selector, "holder")), objective);
        if (score == null) {
            known(raw, "absent", "current_native_scoreboard", "native_score_entry", "full_target", ContractJson.newObject().put("objectivePresent", true)); return;
        }
        ObjectNode payload = ContractJson.newObject().put("objectivePresent", true).put("value", score.value())
                .put("locked", score.isLocked()).put("numberFormatPresent", score.numberFormat() != null);
        try { payload.set("nativeScoreNbt", scoreNbt(level, objective, text(selector, "holder"), score)); }
        catch (ContractException exception) {
            if (!"NATIVE_SERIALIZATION_INCOMPLETE".equals(exception.code())) throw exception;
            unknown(raw, "native_score_codec_incomplete", "native_score_entry"); return;
        }
        if (scoreboard.getObjective(text(selector, "objective")) != objective
                || scoreboard.getPlayerScoreInfo(ScoreHolder.forNameOnly(text(selector, "holder")), objective) != score) {
            throw new ContractException("TARGET_DRIFT", "The actual native score identity changed during serialization");
        }
        known(raw, "present", "current_native_scoreboard", "native_score_entry", "full_target", payload);
    }

    private static void objective(ServerLevel level, ObjectNode selector, ObjectNode raw) {
        var scoreboard = level.getScoreboard(); Objective actual = scoreboard.getObjective(text(selector, "objective"));
        if (actual == null) {
            known(raw, "absent", "current_native_scoreboard", "native_objective_and_all_scores", "full_target", ContractJson.newObject()); return;
        }
        if (!text(selector, "objective").equals(actual.getName())) throw new ContractException("TARGET_IDENTITY_MISMATCH", "Native objective name differs from the selected map membership");
        if (!(scoreboard instanceof ScoreboardReadAccess access)) {
            unknown(raw, "native_scoreboard_read_access_unavailable", "native_objective_and_all_scores"); return;
        }
        // Both public holder-list APIs eagerly allocate. These exact-version
        // accessor views let us reject excessive cardinality before any copy.
        var currentHolders = access.mmmm$playerScores(); var currentSlots = access.mmmm$displayObjectives();
        if (currentHolders == null || currentSlots == null) throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native scoreboard views are unavailable");
        if (currentHolders.size() > MAX_SCORE_HOLDERS || currentSlots.size() > MAX_DISPLAY_SLOTS) throw limit();
        int holderCount = currentHolders.size(); var holders = new ArrayList<String>(holderCount); int holderBytes = 0;
        for (String holder : currentHolders.keySet()) {
            if (holders.size() >= MAX_SCORE_HOLDERS || holder == null || holder.length() > MAX_TAG_BYTES / 3) throw limit();
            holderBytes = Math.addExact(holderBytes, holder.getBytes(StandardCharsets.UTF_8).length);
            if (holderBytes > MAX_RAW_BYTES / 2) throw limit(); holders.add(holder);
        }
        if (holders.size() != holderCount) throw new ContractException("TARGET_DRIFT", "Native scoreboard holder membership changed during enumeration");
        holders.sort(String::compareTo);
        ObjectNode payload = ContractJson.newObject(); var budget = new RawBudget();
        try {
            ObjectNode metadata = serialize(level, output -> output.store("objective", Objective.Packed.CODEC, actual.pack()));
            budget.add(metadata); payload.set("nativeObjectiveNbt", metadata);
            var entries = payload.putArray("scores");
            for (String holder : holders) {
                ReadOnlyScoreInfo score = scoreboard.getPlayerScoreInfo(ScoreHolder.forNameOnly(holder), actual);
                if (score == null) continue;
                ObjectNode entry = ContractJson.newObject().put("holder", holder).put("value", score.value()).put("locked", score.isLocked());
                entry.set("nativeScoreNbt", scoreNbt(level, actual, holder, score)); budget.add(entry); entries.add(entry);
            }
        } catch (ContractException exception) {
            if (!"NATIVE_SERIALIZATION_INCOMPLETE".equals(exception.code())) throw exception;
            unknown(raw, "native_objective_or_score_codec_incomplete", "native_objective_and_all_scores"); return;
        }
        var slots = payload.putArray("displaySlots"); int slotCount = 0;
        // Native slots are enum-valued and the existing map has already passed
        // its cardinality budget. Only references to this exact objective are
        // affected by its removal.
        for (DisplaySlot slot : DisplaySlot.values()) {
            if (++slotCount > MAX_DISPLAY_SLOTS) throw limit();
            if (currentSlots.get(slot) == actual) slots.add(ContractJson.newObject().put("id", slot.id()).put("name", slot.getSerializedName()));
        }
        for (DisplaySlot slot : currentSlots.keySet()) if (slot == null) throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native scoreboard has an invalid display slot");
        budget.add(slots);
        if (scoreboard.getObjective(text(selector, "objective")) != actual || currentHolders.size() != holderCount
                || !currentHolders.keySet().containsAll(holders)) throw new ContractException("TARGET_DRIFT", "Native objective membership changed during serialization");
        known(raw, "present", "current_native_scoreboard", "native_objective_and_all_scores", "full_target", payload);
    }

    private static ObjectNode scoreNbt(ServerLevel level, Objective objective, String holder, ReadOnlyScoreInfo info) {
        if (!(info instanceof Score actual) || actual.getClass() != Score.class) {
            throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native score implementation is outside the admitted persisted codec");
        }
        // This is the same native record/codec used by Scoreboard.packPlayerScores:
        // it retains value, lock, display component and number-format metadata.
        var packed = new Scoreboard.PackedScore(holder, objective.getName(), actual.pack());
        return serialize(level, output -> output.store("score", Scoreboard.PackedScore.CODEC, packed));
    }

    private static void storage(ServerLevel level, ObjectNode selector, ObjectNode raw, CommandStorage storage) {
        if (storage == null || storage.getClass() != CommandStorage.class) {
            unknown(raw, "native_storage_source_not_admitted", "native_storage_key"); return;
        }
        // Verified 26.3 keys() only streams the current namespace/container maps. It never loads SavedData.
        // Exact membership proves the following get() is a same-thread namespace cache hit.
        net.minecraft.resources.Identifier observedId = null; int scanned = 0;
        try (var keys = storage.keys()) {
            var iterator = keys.iterator();
            while (iterator.hasNext()) {
                if (++scanned > 4096) throw limit();
                var id = iterator.next();
                if (text(selector, "storage").equals(id.toString())) { observedId = id; break; }
            }
        }
        if (observedId == null) {
            unknown(raw, "native_storage_namespace_not_observed", "native_storage_key"); return;
        }
        requireThread(level);
        CompoundTag root = storage.get(observedId);
        Tag states = root.get("states");
        ObjectNode payload = ContractJson.newObject().put("storagePresent", true);
        if (states == null) {
            payload.put("statesPresent", false);
            known(raw, "absent", "current_cached_command_storage", "native_storage_key", "full_target", payload); return;
        }
        if (!(states instanceof CompoundTag compound)) {
            payload.set("nativeStatesNbt", serializeTag(states));
            known(raw, "unknown", "current_cached_command_storage", "native_storage_parent", "tracked_changes_only", payload);
            raw.put("status", "unknown").put("reason", "native_storage_parent_is_not_a_compound"); return;
        }
        Tag actual = compound.get(text(selector, "key"));
        payload.put("statesPresent", true);
        if (actual == null) {
            known(raw, "absent", "current_cached_command_storage", "native_storage_key", "full_target", payload); return;
        }
        payload.set("nativeValueNbt", serializeTag(actual));
        known(raw, "present", "current_cached_command_storage", "native_storage_key", "full_target", payload);
    }

    private static ObjectNode serialize(ServerLevel level, Consumer<TagValueOutput> nativeSave) {
        ProblemReporter reporter = new ProblemReporter() {
            @Override public ProblemReporter forChild(PathElement path) { return this; }
            @Override public void report(Problem problem) {
                throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native serializer reported an incomplete observation");
            }
        };
        TagValueOutput output = TagValueOutput.createWithContext(reporter, level.registryAccess());
        try { nativeSave.accept(output); }
        catch (ContractException exception) { throw exception; }
        catch (RuntimeException exception) { throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native codec failed to encode its actual persisted state"); }
        CompoundTag nativeTag = output.buildResult();
        requireNbtBudget(nativeTag);
        BoundedOutput bytes = new BoundedOutput();
        try (DataOutputStream writer = new DataOutputStream(bytes)) { NbtIo.write(nativeTag, writer); }
        catch (IOException exception) { throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native NBT could not be serialized"); }
        byte[] value = bytes.bytes();
        return ContractJson.newObject().put("format", "minecraft.nbt.named-compound/uncompressed")
                .put("bytesHex", HexFormat.of().formatHex(value)).put("sha256", ContractJson.sha256(value));
    }

    private static ObjectNode serializeTag(Tag actual) {
        requireNbtBudget(actual);
        BoundedOutput bytes = new BoundedOutput();
        try (DataOutputStream writer = new DataOutputStream(bytes)) { NbtIo.writeAnyTag(actual, writer); }
        catch (IOException exception) { throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native tag could not be serialized"); }
        byte[] value = bytes.bytes();
        return ContractJson.newObject().put("format", "minecraft.nbt.any-tag/uncompressed")
                .put("bytesHex", HexFormat.of().formatHex(value)).put("sha256", ContractJson.sha256(value));
    }

    /** Bound recursive native writer input without performing recursive traversal ourselves. */
    private static void requireNbtBudget(Tag root) {
        record Pending(Tag tag, int depth) { }
        var pending = new ArrayDeque<Pending>(); pending.add(new Pending(root, 0)); int nodes = 0;
        while (!pending.isEmpty()) {
            Pending current = pending.removeLast();
            if (++nodes > MAX_NBT_NODES || current.depth() > MAX_NBT_DEPTH) throw limit();
            Tag tag = current.tag();
            if (tag.getClass().getClassLoader() != Tag.class.getClassLoader()
                    || tag.getClass().getProtectionDomain().getCodeSource() == null
                    || Tag.class.getProtectionDomain().getCodeSource() == null
                    || !tag.getClass().getProtectionDomain().getCodeSource().getLocation()
                    .equals(Tag.class.getProtectionDomain().getCodeSource().getLocation())) {
                throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native tag source is outside the admitted game implementation");
            }
            if (tag instanceof CompoundTag compound) {
                if (compound.size() > MAX_NBT_CONTAINER_ENTRIES) throw limit();
                for (var entry : compound.entrySet()) {
                    if (entry.getKey().length() > MAX_NATIVE_BYTES / 3) throw limit();
                    pending.add(new Pending(entry.getValue(), current.depth() + 1));
                }
            } else if (tag instanceof ListTag children) {
                if (children.size() > MAX_NBT_CONTAINER_ENTRIES) throw limit();
                for (Tag child : children) pending.add(new Pending(child, current.depth() + 1));
            } else if (tag instanceof StringTag string) {
                if (string.value().length() > MAX_NATIVE_BYTES / 3) throw limit();
            } else if (tag instanceof CollectionTag array && NATIVE_LEAF_CLASSES.contains(tag.getClass().getName())) {
                if (array.size() > MAX_NBT_CONTAINER_ENTRIES) throw limit();
            } else if (!NATIVE_LEAF_CLASSES.contains(tag.getClass().getName())) {
                throw new ContractException("NATIVE_SERIALIZATION_INCOMPLETE", "Native tag implementation is not an admitted bounded observation type");
            }
            if (pending.size() > MAX_NBT_NODES - nodes) throw limit();
        }
    }

    private static BlockPos requirePosition(LoadedChunks chunks, ServerLevel level, ObjectNode context, ObjectNode selector) {
        requireThread(level); requireLevel(level, context);
        if (!text(selector, "dimension").equals(level.dimension().identifier().toString())) throw invalid();
        BlockPos position = NativeBlocks.position(selector.path("position"));
        NativeBlocks.requireScope(context, text(selector, "dimension"), position); chunks.require(level, position);
        return position;
    }
    private static void requireResource(ObjectNode context, ObjectNode selector, ResourceAuthority resources) {
        String requested = text(selector, "resourceId"); boolean included = false;
        for (JsonNode resource : context.path("scope").path("resourceIds")) included |= requested.equals(resource.asText());
        if (!included) throw new ContractException("SCOPE_DENIED", "Native resource is outside the installed explicit resource scope");
        resources.require(context.deepCopy(), selector.deepCopy());
    }
    private static void requireThread(ServerLevel level) {
        if (!Objects.requireNonNull(level).getServer().isSameThread()) throw new ContractException("WRONG_THREAD", "Native target reads require the server thread");
    }
    private static void requireLevel(ServerLevel level, ObjectNode context) {
        if (!level.dimension().identifier().toString().equals(context.path("dimension").asText())) {
            throw new ContractException("CONTEXT_SCOPE_MISMATCH", "Native target level differs from the installed context");
        }
    }
    private static ObjectNode base(ObjectNode selector) {
        ObjectNode raw = ContractJson.newObject().put("format", "mmmm.native.target/1"); raw.set("selector", selector.deepCopy());
        return raw.put("status", "unknown").put("presence", "unknown").put("membershipScope", "unknown")
                .put("captureScope", "unknown").put("coverage", "best_effort").putNull("reason").putNull("payload");
    }
    private static void known(ObjectNode raw, String presence, String membership, String capture, String coverage, ObjectNode payload) {
        raw.put("status", "known").put("presence", presence).put("membershipScope", membership).put("captureScope", capture)
                .put("coverage", coverage).putNull("reason"); raw.set("payload", payload);
    }
    private static void unknown(ObjectNode raw, String reason, String capture) {
        raw.put("status", "unknown").put("presence", "unknown").put("membershipScope", "unknown")
                .put("captureScope", capture).put("coverage", "best_effort").put("reason", reason).putNull("payload");
    }
    private static void validateSelector(ObjectNode selector, String kind) {
        Set<String> fields = switch (kind) {
            case "block_state", "block_entity" -> Set.of("kind", "dimension", "position");
            case "entity" -> Set.of("kind", "dimension", "uuid", "expectedType");
            case "storage" -> Set.of("kind", "storage", "key", "resourceId");
            case "score" -> Set.of("kind", "objective", "holder", "resourceId");
            case "objective" -> Set.of("kind", "objective", "resourceId");
            default -> throw invalid();
        };
        if (selector.size() != fields.size()) throw invalid();
        selector.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); });
        for (String field : fields) if (!"position".equals(field) && !selector.path(field).isTextual()) throw invalid();
        if (selector.has("dimension")) location(text(selector, "dimension"));
        if (selector.has("expectedType")) location(text(selector, "expectedType"));
        if (selector.has("position")) NativeBlocks.position(selector.path("position"));
        if (selector.has("uuid")) uuid(text(selector, "uuid"));
        if (selector.has("storage")) location(text(selector, "storage"));
        for (String field : Set.of("key", "objective", "holder")) if (selector.has(field)) {
            String value = text(selector, field);
            if (value.isEmpty() || value.length() > 128 || !value.matches("[A-Za-z0-9_.#-]+") || "*".equals(value)) throw invalid();
        }
        // The Rust command codec uses states.<key>. Arbitrary NBT-path syntax cannot be treated as one literal leaf.
        if (selector.has("key") && !text(selector, "key").matches("[A-Za-z0-9_-]+")) throw invalid();
        if (selector.has("resourceId") && !text(selector, "resourceId").matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid();
    }
    private static void location(String value) {
        if (value.length() > 256 || !value.matches("[a-z0-9_.-]+:[a-z0-9_./-]+")) throw invalid();
    }
    private static UUID uuid(String value) {
        try { UUID result = UUID.fromString(value); if (!result.toString().equals(value)) throw invalid(); return result; }
        catch (IllegalArgumentException exception) { throw invalid(); }
    }
    private static String text(ObjectNode input, String field) {
        if (!input.path(field).isTextual()) throw invalid(); return input.path(field).asText();
    }
    private static ContractException invalid() { return new ContractException("TARGET_SELECTOR_INVALID", "Native target selector is not an exact supported selector"); }
    private static ContractException limit() { return new ContractException("NATIVE_TARGET_LIMIT", "Native target observation exceeds its finite budget"); }

    static final class Observation {
        private final ObjectNode raw;
        private final byte[] bytes;
        private final String sha256;
        private final long fromTick;
        private final long toTick;
        private Observation(ObjectNode raw, byte[] bytes, long fromTick, long toTick) {
            this.raw = raw.deepCopy(); this.bytes = bytes.clone(); this.sha256 = ContractJson.sha256(bytes);
            this.fromTick = fromTick; this.toTick = toTick;
        }
        ObjectNode raw() { return raw.deepCopy(); }
        byte[] bytes() { return bytes.clone(); }
        String sha256() { return sha256; }
        long fromTick() { return fromTick; }
        long toTick() { return toTick; }
    }
    private static final class BoundedOutput extends OutputStream {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        @Override public void write(int value) { charge(1); bytes.write(value); }
        @Override public void write(byte[] value, int offset, int length) {
            Objects.checkFromIndexSize(offset, length, value.length); charge(length); bytes.write(value, offset, length);
        }
        private void charge(int amount) { if (amount > MAX_NATIVE_BYTES - bytes.size()) throw limit(); }
        byte[] bytes() { return bytes.toByteArray(); }
    }
    private static final class RawBudget {
        private int remaining = MAX_RAW_BYTES - MAX_SELECTOR_BYTES - 4096;
        private void add(JsonNode value) {
            int bytes = ContractJson.bytes(value).length;
            if (bytes > remaining) throw limit(); remaining -= bytes;
        }
    }
}
