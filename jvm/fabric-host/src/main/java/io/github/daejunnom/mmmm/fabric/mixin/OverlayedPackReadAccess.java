package io.github.daejunnom.mmmm.fabric.mixin;

import java.util.List;
import net.minecraft.server.packs.OverlayedPackResources;
import net.minecraft.server.packs.PackMetadataResources;
import net.minecraft.server.packs.PackResources;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** constructor가 이미 구성한 실제 조회 순서와 primary metadata 관계만 읽는다. */
@Mixin(OverlayedPackResources.class)
public interface OverlayedPackReadAccess {
    @Accessor("primaryPackMetadataResources") PackMetadataResources mmmm$primaryPackMetadataResources();
    @Accessor("packResourcesStack") List<PackResources> mmmm$packResourcesStack();
}
