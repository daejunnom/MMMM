package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.resources.Identifier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.storage.CommandStorage;

/** Actual current context and cache-only storage reads shared by full calibration images. */
final class NativeCalibrationStateReader {
    private static final int MAX_STORAGE_KEYS = 4096;
    private NativeCalibrationStateReader() { }
    @FunctionalInterface interface Checkpoint { void check(); }
    @FunctionalInterface interface ContextRead<T> { T read(ObjectNode context, Checkpoint checkpoint); }
    enum Unknown { STORAGE_NOT_CACHED, STORAGE_NOT_ADMITTED }
    record StorageRead(CompoundTag cachedRoot, Unknown unknown) {
        StorageRead {
            if ((cachedRoot == null) == (unknown == null)) throw new IllegalArgumentException("Exactly one storage observation is required");
        }
    }

    static <T> T currentContext(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode supplied,
                                Checkpoint control, ContextRead<T> read) {
        Objects.requireNonNull(server); Objects.requireNonNull(level); Objects.requireNonNull(owner);
        Objects.requireNonNull(supplied); Objects.requireNonNull(control); Objects.requireNonNull(read);
        Checkpoint base = () -> {
            control.check(); owner.checkOpen();
            if (level.getServer() != server || !server.isSameThread()) throw failure("CALIBRATION_STATE_THREAD_REQUIRED");
            // Native 26.3 is levels Map.get only, with no discovery/load.
            if (server.getLevel(level.dimension()) != level) throw failure("CALIBRATION_STATE_CHANGED");
            control.check();
        };
        return withContext(() -> owner.context(text(supplied, "contextId")), supplied, base, context -> {
            Checkpoint checkpoint = () -> {
                base.check();
                if (!"server".equals(owner.side()) || !"game".equals(context.path("environment").path("kind").asText())
                        || !"server".equals(context.path("environment").path("side").asText())
                        || !owner.context(text(context, "contextId")).equals(context)
                        || !level.dimension().identifier().toString().equals(text(context, "dimension"))) {
                    throw failure("CALIBRATION_STATE_CONTEXT_CHANGED");
                }
                base.check();
            };
            checkpoint.check(); return checked(() -> read.read(context, checkpoint), checkpoint);
        });
    }

    /** No get() until the complete bounded cached-key membership has succeeded. */
    static StorageRead cachedStorage(MinecraftServer server, String expected, Checkpoint checkpoint) {
        checkpoint.check();
        return checked(() -> {
            CommandStorage storage = server.getCommandStorage();
            if (storage == null || storage.getClass() != CommandStorage.class) return new StorageRead(null, Unknown.STORAGE_NOT_ADMITTED);
            Identifier observed;
            try (var keys = storage.keys()) { observed = cachedKey(keys.iterator(), expected, checkpoint); }
            checkpoint.check();
            if (observed == null) return new StorageRead(null, Unknown.STORAGE_NOT_CACHED);
            if (server.getCommandStorage() != storage) throw failure("CALIBRATION_STATE_CHANGED");
            CompoundTag root = storage.get(observed);
            checkpoint.check();
            if (root == null || root.getClass() != CompoundTag.class) return new StorageRead(null, Unknown.STORAGE_NOT_ADMITTED);
            return new StorageRead(root, null);
        }, checkpoint);
    }

    /** Comparison test port; only currentContext() supplies the actual owner lookup. */
    static <T> T withContext(Supplier<ObjectNode> installed, ObjectNode supplied, Checkpoint original, Function<ObjectNode, T> read) {
        original.check();
        return checked(() -> {
            ObjectNode context = Objects.requireNonNull(installed.get());
            if (!context.equals(supplied)) throw failure("CALIBRATION_STATE_CONTEXT_CHANGED");
            original.check(); return read.apply(context);
        }, original);
    }

    /** An early match cannot skip the finite complete-membership check. */
    static <K> K cachedKey(Iterator<K> keys, String expected, Checkpoint checkpoint) {
        K observed = null; int count = 0;
        while (keys.hasNext()) {
            checkpoint.check(); if (++count > MAX_STORAGE_KEYS) throw failure("CALIBRATION_STATE_LIMIT");
            K key = keys.next(); if (key == null) throw failure("CALIBRATION_STATE_CHANGED");
            if (expected.equals(key.toString())) { if (observed != null) throw failure("CALIBRATION_STATE_CHANGED"); observed = key; }
        }
        checkpoint.check(); return observed;
    }

    static <T> T checked(Supplier<T> read, Checkpoint checkpoint) {
        Throwable primary = null;
        try { return read.get(); }
        catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            try { checkpoint.check(); }
            catch (RuntimeException | Error after) { if (primary == null) throw after; if (after != primary) primary.addSuppressed(after); }
        }
    }
    private static String text(ObjectNode value, String field) {
        if (!value.path(field).isTextual()) throw failure("CALIBRATION_STATE_CONTEXT_CHANGED"); return value.path(field).textValue();
    }
    private static ContractException failure(String code) { return new ContractException(code, "The original fixed calibration state is unavailable or changed"); }
}
