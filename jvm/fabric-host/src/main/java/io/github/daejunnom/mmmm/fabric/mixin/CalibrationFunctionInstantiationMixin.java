package io.github.daejunnom.mmmm.fabric.mixin;

import com.mojang.brigadier.CommandDispatcher;
import io.github.daejunnom.mmmm.fabric.NativeCalibrationStageHooks;
import net.minecraft.commands.CommandResultCallback;
import net.minecraft.commands.ExecutionCommandSource;
import net.minecraft.commands.FunctionInstantiationException;
import net.minecraft.commands.execution.ExecutionControl;
import net.minecraft.commands.functions.CommandFunction;
import net.minecraft.commands.functions.InstantiatedFunction;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.resources.Identifier;
import net.minecraft.server.commands.FunctionCommand;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/** Observes the exact native instantiation reached by the function command.
 * It neither instantiates a second time nor reconstructs a loaded function. */
@Mixin(FunctionCommand.class)
public abstract class CalibrationFunctionInstantiationMixin {
    @SuppressWarnings({"rawtypes", "unchecked"})
    @Redirect(method = "instantiateAndQueueFunctions(Lnet/minecraft/nbt/CompoundTag;Lnet/minecraft/commands/execution/ExecutionControl;Lcom/mojang/brigadier/CommandDispatcher;Lnet/minecraft/commands/ExecutionCommandSource;Lnet/minecraft/commands/functions/CommandFunction;Lnet/minecraft/resources/Identifier;Lnet/minecraft/commands/CommandResultCallback;Z)V",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/commands/functions/CommandFunction;instantiate(Lnet/minecraft/nbt/CompoundTag;Lcom/mojang/brigadier/CommandDispatcher;)Lnet/minecraft/commands/functions/InstantiatedFunction;"),
            require = 1, allow = 1)
    private static InstantiatedFunction mmmm$observeActualInstantiation(CommandFunction actualPlain, CompoundTag actualArguments,
            CommandDispatcher actualDispatcher, CompoundTag originalArguments, ExecutionControl actualControl,
            CommandDispatcher originalDispatcher, ExecutionCommandSource actualSource, CommandFunction originalPlain,
            Identifier originalIdentifier, CommandResultCallback originalCallback, boolean returnParentFrame)
            throws FunctionInstantiationException {
        return NativeCalibrationStageHooks.<InstantiatedFunction>nativeFunctionInstantiation(actualPlain, actualSource, actualControl,
                () -> actualControl.currentFrame(), actual -> actual.entries(), () -> actualPlain.instantiate(actualArguments, actualDispatcher));
    }
}
