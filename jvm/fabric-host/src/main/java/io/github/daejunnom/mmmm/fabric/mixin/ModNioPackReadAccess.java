package io.github.daejunnom.mmmm.fabric.mixin;

import java.nio.file.Path;
import java.util.List;
import net.fabricmc.fabric.impl.resource.pack.ModNioPackResources;
import net.minecraft.server.packs.PackType;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** 고정한 Fabric 구현 필드는 remap하지 않으며 실제 객체의 경로와 type만 읽는다. */
@Mixin(value = ModNioPackResources.class, remap = false)
public interface ModNioPackReadAccess {
    @Accessor(value = "basePaths", remap = false) List<Path> mmmm$basePaths();
    @Accessor(value = "type", remap = false) PackType mmmm$type();
}
