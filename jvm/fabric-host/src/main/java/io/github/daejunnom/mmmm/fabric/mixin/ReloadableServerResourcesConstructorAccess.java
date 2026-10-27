package io.github.daejunnom.mmmm.fabric.mixin;

import java.util.List;
import net.minecraft.commands.Commands;
import net.minecraft.server.ReloadableServerRegistries;
import net.minecraft.server.ReloadableServerResources;
import net.minecraft.server.permissions.PermissionSet;
import net.minecraft.world.flag.FeatureFlagSet;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Invoker;

/** Invokes the actual six-argument native constructor; it issues no observation authority. */
@Mixin(ReloadableServerResources.class)
public interface ReloadableServerResourcesConstructorAccess {
    @Invoker("<init>")
    static ReloadableServerResources mmmm$createActual(ReloadableServerRegistries.LoadResult loadResult,
            FeatureFlagSet features, Commands.CommandSelection selection, List<?> pendingTags,
            PermissionSet permissions, List<?> pendingComponents) {
        throw new AssertionError("The native resources constructor invoker was not transformed");
    }
}
