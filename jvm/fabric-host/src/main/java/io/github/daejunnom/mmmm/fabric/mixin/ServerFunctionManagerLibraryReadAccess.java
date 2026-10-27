package io.github.daejunnom.mmmm.fabric.mixin;

import net.minecraft.server.ServerFunctionLibrary;
import net.minecraft.server.ServerFunctionManager;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** Read the actual installed library; this accessor does not grant source admission. */
@Mixin(ServerFunctionManager.class)
public interface ServerFunctionManagerLibraryReadAccess {
    @Accessor("library") ServerFunctionLibrary mmmm$library();
}
