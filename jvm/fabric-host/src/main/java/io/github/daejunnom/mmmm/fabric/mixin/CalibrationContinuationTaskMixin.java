package io.github.daejunnom.mmmm.fabric.mixin;

import io.github.daejunnom.mmmm.fabric.NativeCalibrationStageHooks;
import net.minecraft.commands.execution.CommandQueueEntry;
import net.minecraft.commands.execution.Frame;
import net.minecraft.commands.execution.tasks.ContinuationTask;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/** Observes both the direct small-list and continuing native provider callsites.
 * The original provider is called once with the original frame and argument. */
@Mixin(ContinuationTask.class)
public abstract class CalibrationContinuationTaskMixin {
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Redirect(method = "schedule(Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;Ljava/util/List;Lnet/minecraft/commands/execution/tasks/ContinuationTask$TaskProvider;)V",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/commands/execution/tasks/ContinuationTask$TaskProvider;create(Lnet/minecraft/commands/execution/Frame;Ljava/lang/Object;)Lnet/minecraft/commands/execution/CommandQueueEntry;"),
            require = 3, allow = 3)
    private static CommandQueueEntry mmmm$observeScheduledTask(ContinuationTask.TaskProvider actualProvider, Frame frame, Object argument) {
        return NativeCalibrationStageHooks.nativeTaskCreate(actualProvider, frame, argument, () -> actualProvider.create(frame, argument));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Redirect(method = "execute(Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;)V",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/commands/execution/tasks/ContinuationTask$TaskProvider;create(Lnet/minecraft/commands/execution/Frame;Ljava/lang/Object;)Lnet/minecraft/commands/execution/CommandQueueEntry;"),
            require = 1, allow = 1)
    private CommandQueueEntry mmmm$observeContinuingTask(ContinuationTask.TaskProvider actualProvider, Frame frame, Object argument) {
        return NativeCalibrationStageHooks.nativeTaskCreate(actualProvider, frame, argument, () -> actualProvider.create(frame, argument));
    }
}
