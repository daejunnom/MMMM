package io.github.daejunnom.mmmm.fabric.mixin;

import com.mojang.brigadier.context.ContextChain;
import io.github.daejunnom.mmmm.fabric.NativeCalibrationStageHooks;
import java.util.List;
import net.minecraft.commands.ExecutionCommandSource;
import net.minecraft.commands.execution.ChainModifiers;
import net.minecraft.commands.execution.CustomCommandExecutor;
import net.minecraft.commands.execution.CustomModifierExecutor;
import net.minecraft.commands.execution.ExecutionContext;
import net.minecraft.commands.execution.ExecutionControl;
import net.minecraft.commands.execution.Frame;
import net.minecraft.commands.execution.tasks.BuildContexts;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/** Exact 26.3 custom callsites keep their original queue/ExecutionControl.
 * Raw erasure is confined to these verified native erased descriptors. */
@Mixin(BuildContexts.class)
public abstract class CalibrationCustomExecutionMixin {
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Redirect(method = "execute(Lnet/minecraft/commands/ExecutionCommandSource;Ljava/util/List;Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;Lnet/minecraft/commands/execution/ChainModifiers;)V",
        at = @At(value = "INVOKE", target = "Lnet/minecraft/commands/execution/CustomModifierExecutor;apply(Ljava/lang/Object;Ljava/util/List;Lcom/mojang/brigadier/context/ContextChain;Lnet/minecraft/commands/execution/ChainModifiers;Lnet/minecraft/commands/execution/ExecutionControl;)V"))
    private void mmmm$observeModifier(CustomModifierExecutor actual, Object source, List sources, ContextChain chain, ChainModifiers modifiers, ExecutionControl control,
            ExecutionCommandSource originalSource, List originalSources, ExecutionContext context, Frame frame, ChainModifiers originalModifiers) {
        NativeCalibrationStageHooks.nativeCustom(actual, chain, frame, true, () -> actual.apply(source, sources, chain, modifiers, control));
    }
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Redirect(method = "execute(Lnet/minecraft/commands/ExecutionCommandSource;Ljava/util/List;Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;Lnet/minecraft/commands/execution/ChainModifiers;)V",
        at = @At(value = "INVOKE", target = "Lnet/minecraft/commands/execution/CustomCommandExecutor;run(Ljava/lang/Object;Lcom/mojang/brigadier/context/ContextChain;Lnet/minecraft/commands/execution/ChainModifiers;Lnet/minecraft/commands/execution/ExecutionControl;)V"))
    private void mmmm$observeCommand(CustomCommandExecutor actual, Object source, ContextChain chain, ChainModifiers modifiers, ExecutionControl control,
            ExecutionCommandSource originalSource, List originalSources, ExecutionContext context, Frame frame, ChainModifiers originalModifiers) {
        NativeCalibrationStageHooks.nativeCustom(actual, chain, frame, false, () -> actual.run(source, chain, modifiers, control));
    }
}
