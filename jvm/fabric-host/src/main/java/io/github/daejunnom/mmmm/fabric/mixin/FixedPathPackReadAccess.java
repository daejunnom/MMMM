package io.github.daejunnom.mmmm.fabric.mixin;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import net.minecraft.server.packs.FixedPathPackResources;
import net.minecraft.server.packs.PackType;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** 실제 26.3 객체의 root metadata 경로와 type별 resource 경로를 읽기만 한다. */
@Mixin(FixedPathPackResources.class)
public interface FixedPathPackReadAccess {
    @Accessor("rootPaths") List<Path> mmmm$rootPaths();
    @Accessor("pathsForType") Map<PackType, List<Path>> mmmm$pathsForType();
}
