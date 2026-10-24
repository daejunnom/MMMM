package io.github.daejunnom.mmmm.fabric.mixin;

import net.minecraft.world.level.saveddata.SavedDataType;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Invoker;

/** Calls the original native type factory; equal caller-authored type IDs never become grants. */
@Mixin(targets = "net.minecraft.world.level.storage.CommandStorage$Container")
public interface CommandStorageContainerBootstrapAccess {
    @Invoker("type")
    static SavedDataType<?> mmmm$bootstrapType(String namespace) {
        throw new AssertionError("The original command-storage Container type invoker is unavailable");
    }
}
