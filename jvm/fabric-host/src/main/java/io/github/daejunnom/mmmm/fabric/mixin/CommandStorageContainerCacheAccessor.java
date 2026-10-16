package io.github.daejunnom.mmmm.fabric.mixin;

import java.util.Map;
import net.minecraft.nbt.CompoundTag;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** The package-private native Container is addressed without a Java type or a write accessor. */
@Mixin(targets = "net.minecraft.world.level.storage.CommandStorage$Container")
public interface CommandStorageContainerCacheAccessor {
    @Accessor("storage") Map<String, CompoundTag> mmmm$storage();
}
