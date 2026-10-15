package io.github.daejunnom.mmmm.fabric.mixin;

import com.mojang.brigadier.context.ContextChain;
import net.minecraft.commands.execution.tasks.BuildContexts;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Observes the exact constructor reached by CommandFunction.parseCommand in 26.3.
 * The original native parser alone constructs the entry and compiled chain. */
@Mixin(BuildContexts.Unbound.class)
public abstract class FunctionEntrySourceMixin implements FunctionEntryReadAccess {
    @Unique private String mmmm$originalCommandInput;
    @Unique private ContextChain<?> mmmm$compiledContextChain;

    @Inject(method = "<init>(Ljava/lang/String;Lcom/mojang/brigadier/context/ContextChain;)V", at = @At("RETURN"))
    private void mmmm$observeNativeInputs(String original, ContextChain<?> chain, CallbackInfo callback) {
        mmmm$originalCommandInput = original;
        mmmm$compiledContextChain = chain;
    }

    @Override public String mmmm$originalCommandInput() { return mmmm$originalCommandInput; }
    @Override public ContextChain<?> mmmm$compiledContextChain() { return mmmm$compiledContextChain; }
}
