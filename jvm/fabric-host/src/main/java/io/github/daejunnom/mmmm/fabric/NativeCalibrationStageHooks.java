package io.github.daejunnom.mmmm.fabric;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.ResultConsumer;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.Objects;

/** Internal exact native callsite hooks. No public installer, proof or grant.
 * Outside the private synchronous runner scope the native invocation is unchanged. */
public final class NativeCalibrationStageHooks {
    private static final ThreadLocal<Listener> ACTIVE = new ThreadLocal<>();
    private NativeCalibrationStageHooks() { }

    interface Listener {
        void beforeEntry(Object entry, Object source, Object executionContext, Object frame);
        void beforeHandler(Object handler, CommandContext<?> context);
        void afterHandler(Object handler, CommandContext<?> context, Integer returned, Throwable failure);
        void queueReturned(Object executionContext, int quota, boolean overflow, int queued, int newTopCommands);
        void beforeCustom(Object receiver, Object chain, Object frame, boolean modifier);
        void afterCustom(Object receiver, Object chain, Object frame, boolean modifier, Throwable failure);
        void frameReturned(Object frame, Integer returned);
        default void beforeFrameReturn(Object frame, Integer returned) { }
        default void beforeResultCallback(CommandContext<?> context) { }
        default void afterResultCallback(CommandContext<?> context, Throwable failure) { }
    }
    static final class Scope implements AutoCloseable {
        private final Listener owner;
        private boolean closed;
        private Scope(Listener owner) { this.owner = owner; }
        @Override public void close() {
            if (closed) return;
            closed = true;
            if (ACTIVE.get() != owner) throw new ContractException("CALIBRATION_STAGE_SCOPE_CHANGED", "Native stage owner changed");
            ACTIVE.remove();
        }
    }
    static Scope open(Listener actualRunner) {
        Objects.requireNonNull(actualRunner);
        if (ACTIVE.get() != null) throw new ContractException("CALIBRATION_STAGE_REENTRANT", "Native stage scope is already occupied");
        ACTIVE.set(actualRunner);
        return new Scope(actualRunner);
    }
    public static void nativeEntry(Object entry, Object source, Object context, Object frame) {
        Listener current = ACTIVE.get();
        if (current != null) current.beforeEntry(entry, source, context, frame);
    }
    public static void nativeQueueReturned(Object context, int quota, boolean overflow, int queued, int newTopCommands) {
        Listener current = ACTIVE.get();
        if (current != null) current.queueReturned(context, quota, overflow, queued, newTopCommands);
    }
    public static void nativeCustom(Object receiver, Object chain, Object frame, boolean modifier, Runnable actualCall) {
        Listener current = ACTIVE.get();
        if (current == null) { actualCall.run(); return; }
        current.beforeCustom(receiver, chain, frame, modifier);
        Throwable primary = null;
        try { actualCall.run(); }
        catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            try { current.afterCustom(receiver, chain, frame, modifier, primary); }
            catch (RuntimeException | Error post) {
                if (primary == null) throw post;
                if (primary != post) primary.addSuppressed(post);
            }
        }
    }
    public static void nativeFrameReturned(Object frame, Integer returned) {
        Listener current = ACTIVE.get();
        if (current != null) current.frameReturned(frame, returned);
    }
    public static void nativeBeforeFrameReturn(Object frame, Integer returned) {
        Listener current = ACTIVE.get(); if (current != null) current.beforeFrameReturn(frame, returned);
    }
    public static <S> void nativeResultCallback(ResultConsumer<S> callback, CommandContext<S> context, boolean success, int returned) {
        Listener current = ACTIVE.get();
        if (current == null) { callback.onCommandComplete(context, success, returned); return; }
        current.beforeResultCallback(context); Throwable primary = null;
        try { callback.onCommandComplete(context, success, returned); }
        catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            try { current.afterResultCallback(context, primary); }
            catch (RuntimeException | Error post) { if (primary == null) throw post; if (primary != post) primary.addSuppressed(post); }
        }
    }
    public static <S> int nativeHandler(Command<S> handler, CommandContext<S> context) throws CommandSyntaxException {
        Listener current = ACTIVE.get();
        if (current == null) return handler.run(context);
        current.beforeHandler(handler, context);
        Integer returned = null; Throwable primary = null;
        try {
            returned = handler.run(context);
            return returned;
        } catch (CommandSyntaxException | RuntimeException | Error failure) {
            primary = failure; throw failure;
        } finally {
            try { current.afterHandler(handler, context, returned, primary); }
            catch (RuntimeException | Error post) {
                if (primary == null) throw post;
                if (primary != post) primary.addSuppressed(post);
            }
        }
    }
}
