package io.github.daejunnom.mmmm.fabric.mixin;

import java.util.Map;
import net.minecraft.world.level.storage.CommandStorage;
import net.minecraft.world.level.storage.SavedDataStorage;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** Actual native cache binding; this access alone issues no bootstrap or file authority. */
@Mixin(CommandStorage.class)
public interface CommandStorageBootstrapAccess {
    @Accessor("namespaces") Map<String, Object> mmmm$bootstrapNamespaces();
    @Accessor("savedDataStorage") SavedDataStorage mmmm$bootstrapSavedDataStorage();
}
