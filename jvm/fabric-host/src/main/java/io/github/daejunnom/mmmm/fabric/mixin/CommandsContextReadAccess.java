package io.github.daejunnom.mmmm.fabric.mixin;

import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.commands.execution.ExecutionContext;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** Exact 26.3 native field getter. MMMM never replaces, drains or mutates this context. */
@Mixin(Commands.class)
public interface CommandsContextReadAccess {
    @Accessor("CURRENT_EXECUTION_CONTEXT")
    static ThreadLocal<ExecutionContext<CommandSourceStack>> mmmm$currentExecutionContext() {
        throw new AssertionError("The exact native read accessor has not been installed");
    }
}
