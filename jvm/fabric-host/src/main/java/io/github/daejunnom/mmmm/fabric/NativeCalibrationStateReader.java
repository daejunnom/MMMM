package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;

/** Actual current context and cache-only storage reads shared by full calibration images. */
final class NativeCalibrationStateReader {
    private NativeCalibrationStateReader() { }
    @FunctionalInterface interface Checkpoint { void check(); }
    @FunctionalInterface interface ContextRead<T> { T read(ObjectNode context, Checkpoint checkpoint); }

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

    /** Actual cached namespace and key membership, without get/load or a synthetic root. */
    static NativeCommandStorageCache.Read cachedStorage(MinecraftServer server, String expected, Checkpoint checkpoint) {
        return NativeCommandStorageCache.observe(server, expected, checkpoint);
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
