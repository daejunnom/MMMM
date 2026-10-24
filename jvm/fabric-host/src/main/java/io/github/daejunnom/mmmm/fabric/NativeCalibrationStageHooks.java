package io.github.daejunnom.mmmm.fabric;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.ResultConsumer;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.commands.FunctionInstantiationException;

/** Internal exact native callsite hooks. No public installer, proof or grant.
 * Outside the private synchronous runner scope the native invocation is unchanged. */
public final class NativeCalibrationStageHooks {
    private static final ThreadLocal<Listener> ACTIVE = new ThreadLocal<>();
    private NativeCalibrationStageHooks() { }

    @FunctionalInterface
    public interface FunctionInstantiation<T> {
        T instantiate() throws FunctionInstantiationException;
    }

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
        default void beforeFunctionInstantiation(Object actualPlain, Object actualSource, Object actualExecutionControl,
                Object actualParentFrameCallback, Object actualEntriesCallback, Object actualCallCallback) { }
        default void functionInstantiated(Object actualPlain, Object actualInstantiated, Object actualSource,
                Object actualExecutionControl, Object actualParentFrame, List<?> actualEntries, Throwable actualFailure) { }
        default void functionCall(Object call, Object function, Object source, Object context, Object parentFrame) { }
        default void functionSchedule(Object call, Object function, Object source, Object context, Object parentFrame,
                Object childFrame, List<?> actualEntries, Object provider) { }
        default void beforeTaskCreate(Object provider, Object frame, Object argument) { }
        default void taskCreated(Object provider, Object frame, Object argument, Object actualQueueEntry, Throwable failure) { }
        default void beforeQueueEntry(Object context, Object actualQueueEntry, Object frame, Object action) { }
        default void afterQueueEntry(Object context, Object actualQueueEntry, Object frame, Object action, Throwable failure) { }
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
    public static void nativeFunctionCall(Object call, Object function, Object source, Object context, Object parentFrame) {
        Listener current = ACTIVE.get();
        if (current != null) current.functionCall(call, function, source, context, parentFrame);
    }
    public static <T> T nativeFunctionInstantiation(Object actualPlain, Object actualSource, Object actualExecutionControl,
            Supplier<?> actualParentFrame, Function<T, ? extends List<?>> actualEntries, FunctionInstantiation<T> actualCall)
            throws FunctionInstantiationException {
        Listener current = ACTIVE.get();
        if (current == null) return actualCall.instantiate();
        // A rejected precheck is not an attempted original call or a post-call
        // observation. Pass the actual callbacks without invoking any of them.
        current.beforeFunctionInstantiation(actualPlain, actualSource, actualExecutionControl,
                actualParentFrame, actualEntries, actualCall);
        T returned = null;
        Throwable primary = null;
        try {
            returned = actualCall.instantiate();
            return returned;
        } catch (FunctionInstantiationException | RuntimeException | Error failure) {
            primary = failure;
            throw failure;
        } finally {
            try {
                Object frame = primary == null ? actualParentFrame.get() : null;
                List<?> entries = primary == null && returned != null ? actualEntries.apply(returned) : null;
                current.functionInstantiated(actualPlain, returned, actualSource, actualExecutionControl, frame, entries, primary);
            } catch (RuntimeException | Error post) {
                if (primary == null) throw post;
                preservePrimaryFailure(primary, post);
            }
        }
    }
    public static void nativeFunctionSchedule(Object call, Object function, Object source, Object context, Object parentFrame,
            Object childFrame, List<?> actualEntries, Object provider, Runnable actualCall) {
        Listener current = ACTIVE.get();
        if (current != null) current.functionSchedule(call, function, source, context, parentFrame, childFrame, actualEntries, provider);
        actualCall.run();
    }
    public static <T> T nativeTaskCreate(Object provider, Object frame, Object argument, Supplier<T> actualCall) {
        Listener current = ACTIVE.get();
        if (current == null) return actualCall.get();
        current.beforeTaskCreate(provider, frame, argument);
        T returned = null;
        Throwable primary = null;
        try {
            returned = actualCall.get();
            return returned;
        } catch (RuntimeException | Error failure) {
            primary = failure;
            throw failure;
        } finally {
            try { current.taskCreated(provider, frame, argument, returned, primary); }
            catch (RuntimeException | Error post) {
                if (primary == null) throw post;
                preservePrimaryFailure(primary, post);
            }
        }
    }
    public static void nativeQueueEntry(Object context, Object actualQueueEntry, Supplier<?> actualFrame,
            Supplier<?> actualAction, Runnable actualCall) {
        Listener current = ACTIVE.get();
        if (current == null) { actualCall.run(); return; }
        Object frame = actualFrame.get();
        Object action = actualAction.get();
        current.beforeQueueEntry(context, actualQueueEntry, frame, action);
        Throwable primary = null;
        try { actualCall.run(); }
        catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            try { current.afterQueueEntry(context, actualQueueEntry, frame, action, primary); }
            catch (RuntimeException | Error post) {
                if (primary == null) throw post;
                preservePrimaryFailure(primary, post);
            }
        }
    }
    private static void preservePrimaryFailure(Throwable primary, Throwable post) {
        if (primary == post) return;
        try { primary.addSuppressed(post); }
        catch (RuntimeException | Error suppressionFailure) {
            // Even unavailable suppression storage cannot replace the actual engine failure.
        }
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
