package io.github.daejunnom.mmmm.fabric.mixin;

import io.github.daejunnom.mmmm.fabric.NativeFunctionLoadHookContexts;
import net.minecraft.server.ServerFunctionLibrary;
import net.minecraft.server.ServerFunctionManager;
import org.objectweb.asm.Opcodes;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Relays the actual library installation before the engine's post-reload work. */
@Mixin(ServerFunctionManager.class)
public abstract class LoadedFunctionManagerMixin {
    @Inject(method = "replaceLibrary(Lnet/minecraft/server/ServerFunctionLibrary;)V",
            at = @At(value = "FIELD", target = "Lnet/minecraft/server/ServerFunctionManager;"
                    + "library:Lnet/minecraft/server/ServerFunctionLibrary;",
                    opcode = Opcodes.PUTFIELD, shift = At.Shift.AFTER), require = 1, allow = 1)
    private void mmmm$observeLibraryInstallation(ServerFunctionLibrary actualLibrary, CallbackInfo callback) {
        try {
            NativeFunctionLoadHookContexts.libraryInstalled((ServerFunctionManager) (Object) this, actualLibrary);
        } catch (RuntimeException | Error unavailable) {
            // Missing required installation facts stay unavailable; preserve the engine's post-reload work.
        }
    }
}
