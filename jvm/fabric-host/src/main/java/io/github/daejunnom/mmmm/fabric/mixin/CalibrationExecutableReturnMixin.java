package io.github.daejunnom.mmmm.fabric.mixin;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.ResultConsumer;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.context.ContextChain;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.fabric.NativeCalibrationStageHooks;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/** Exact Brigadier 1.3.11 native terminal Command.run callsite. Custom native
 * executors are separate paths and cannot acquire a fabricated return here. */
@Mixin(value = ContextChain.class, remap = false)
public abstract class CalibrationExecutableReturnMixin {
    @Redirect(method = "runExecutable(Lcom/mojang/brigadier/context/CommandContext;Ljava/lang/Object;Lcom/mojang/brigadier/ResultConsumer;Z)I", at = @At(value = "INVOKE",
            target = "Lcom/mojang/brigadier/Command;run(Lcom/mojang/brigadier/context/CommandContext;)I"), remap = false)
    private static int mmmm$observeActualReturn(Command<Object> actual, CommandContext<Object> context) throws CommandSyntaxException {
        return NativeCalibrationStageHooks.nativeHandler(actual, context);
    }
    @Redirect(method = "runExecutable(Lcom/mojang/brigadier/context/CommandContext;Ljava/lang/Object;Lcom/mojang/brigadier/ResultConsumer;Z)I", at = @At(value = "INVOKE",
            target = "Lcom/mojang/brigadier/ResultConsumer;onCommandComplete(Lcom/mojang/brigadier/context/CommandContext;ZI)V"), remap = false)
    private static void mmmm$guardActualResultCallback(ResultConsumer<Object> actual, CommandContext<Object> context, boolean success, int returned) {
        NativeCalibrationStageHooks.nativeResultCallback(actual, context, success, returned);
    }
}
