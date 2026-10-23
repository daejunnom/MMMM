package io.github.daejunnom.mmmm.fabric.mixin;

import io.github.daejunnom.mmmm.fabric.NativeFunctionLoadObservation;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import net.minecraft.server.packs.resources.Resource;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/** Observes the original stream and reader without opening or decoding another source. */
@Mixin(Resource.class)
public abstract class LoadedFunctionResourceMixin {
    @Redirect(method = "openAsReader()Ljava/io/BufferedReader;",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/server/packs/resources/Resource;open()Ljava/io/InputStream;"),
            require = 1)
    private InputStream mmmm$observeLoaderStream(Resource actualResource) throws IOException {
        // Original engine failures leave this method unchanged, including their identity.
        InputStream actualReturnedStream = actualResource.open();
        try {
            var read = NativeFunctionLoadObservation.forResource(actualResource);
            return read == null ? actualReturnedStream : read.opened(actualResource, actualReturnedStream);
        } catch (RuntimeException | Error unavailable) {
            // A missing required observation remains unavailable; it cannot issue admission.
            return actualReturnedStream;
        }
    }

    @Inject(method = "openAsReader()Ljava/io/BufferedReader;", at = @At("RETURN"), require = 1)
    private void mmmm$observeLoaderReader(CallbackInfoReturnable<BufferedReader> callback) {
        try {
            Resource actualResource = (Resource) (Object) this;
            var read = NativeFunctionLoadObservation.forResource(actualResource);
            if (read != null) read.readerOpened(callback.getReturnValue());
        } catch (RuntimeException | Error unavailable) {
            // Preserve the engine's actual return; incomplete reader facts stay unavailable.
        }
    }
}
