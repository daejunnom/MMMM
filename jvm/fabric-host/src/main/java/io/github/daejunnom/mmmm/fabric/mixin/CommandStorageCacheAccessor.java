package io.github.daejunnom.mmmm.fabric.mixin;

import java.util.Map;
import net.minecraft.world.level.storage.CommandStorage;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** Existing native namespace cache only. Callers never mutate the returned map. */
@Mixin(CommandStorage.class)
public interface CommandStorageCacheAccessor {
    @Accessor("namespaces") Map<String, ?> mmmm$namespaces();
}
