package io.github.daejunnom.mmmm.fabric.mixin;

import io.github.daejunnom.mmmm.fabric.NativeCalibrationStageHooks;
import java.util.List;
import net.minecraft.commands.ExecutionCommandSource;
import net.minecraft.commands.execution.ExecutionContext;
import net.minecraft.commands.execution.Frame;
import net.minecraft.commands.execution.tasks.CallFunction;
import net.minecraft.commands.execution.tasks.ContinuationTask;
import net.minecraft.commands.functions.InstantiatedFunction;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Exact 26.3 call and child-frame scheduling facts. The native function and
 * original provider remain the engine's actual objects, not proof substitutes. */
@Mixin(CallFunction.class)
public abstract class CalibrationFunctionCallMixin {
    @Shadow @Final private InstantiatedFunction<?> function;

    @Inject(method = "execute(Lnet/minecraft/commands/ExecutionCommandSource;Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;)V",
            at = @At("HEAD"), require = 1, allow = 1)
    private void mmmm$observeActualFunction(ExecutionCommandSource<?> source, ExecutionContext<?> context, Frame parentFrame,
            CallbackInfo callback) {
        NativeCalibrationStageHooks.nativeFunctionCall(this, function, source, context, parentFrame);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Redirect(method = "execute(Lnet/minecraft/commands/ExecutionCommandSource;Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;)V",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/commands/execution/tasks/ContinuationTask;schedule(Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;Ljava/util/List;Lnet/minecraft/commands/execution/tasks/ContinuationTask$TaskProvider;)V"),
            require = 1, allow = 1)
    private void mmmm$observeActualSchedule(ExecutionContext actualContext, Frame childFrame, List actualEntries,
            ContinuationTask.TaskProvider actualProvider, ExecutionCommandSource source, ExecutionContext originalContext,
            Frame parentFrame) {
        NativeCalibrationStageHooks.nativeFunctionSchedule(this, function, source, actualContext, parentFrame,
                childFrame, actualEntries, actualProvider,
                () -> ContinuationTask.schedule(actualContext, childFrame, actualEntries, actualProvider));
    }
}
