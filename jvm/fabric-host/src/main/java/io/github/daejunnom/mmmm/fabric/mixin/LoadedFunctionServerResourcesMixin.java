package io.github.daejunnom.mmmm.fabric.mixin;

import io.github.daejunnom.mmmm.fabric.NativeFunctionLoadObservation;
import java.util.List;
import java.util.concurrent.Executor;
import net.minecraft.commands.Commands;
import net.minecraft.server.ReloadableServerRegistries;
import net.minecraft.server.ReloadableServerResources;
import net.minecraft.server.packs.resources.ResourceManager;
import net.minecraft.server.permissions.PermissionSet;
import net.minecraft.world.flag.FeatureFlagSet;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/** Joins the native resources construction to its actual enclosing manager argument. */
@Mixin(ReloadableServerResources.class)
public abstract class LoadedFunctionServerResourcesMixin {
    @Redirect(method = "lambda$loadResources$2(Lnet/minecraft/server/ReloadableServerRegistries$LoadResult;"
            + "Lnet/minecraft/world/flag/FeatureFlagSet;Lnet/minecraft/commands/Commands$CommandSelection;"
            + "Ljava/util/List;Lnet/minecraft/server/permissions/PermissionSet;"
            + "Lnet/minecraft/server/packs/resources/ResourceManager;Ljava/util/concurrent/Executor;"
            + "Ljava/util/concurrent/Executor;Ljava/util/List;)Ljava/util/concurrent/CompletionStage;",
            at = @At(value = "NEW", target = "(Lnet/minecraft/server/ReloadableServerRegistries$LoadResult;"
                    + "Lnet/minecraft/world/flag/FeatureFlagSet;Lnet/minecraft/commands/Commands$CommandSelection;"
                    + "Ljava/util/List;Lnet/minecraft/server/permissions/PermissionSet;Ljava/util/List;)"
                    + "Lnet/minecraft/server/ReloadableServerResources;"), require = 1)
    private static ReloadableServerResources mmmm$observeResourcesConstruction(
            ReloadableServerRegistries.LoadResult constructorLoadResult,
            FeatureFlagSet constructorFeatures, Commands.CommandSelection constructorSelection,
            List<?> constructorPendingTags, PermissionSet constructorPermissions, List<?> constructorComponents,
            ReloadableServerRegistries.LoadResult methodLoadResult,
            FeatureFlagSet methodFeatures, Commands.CommandSelection methodSelection,
            List<?> methodPendingTags, PermissionSet methodPermissions, ResourceManager actualManager,
            Executor prepareExecutor, Executor applyExecutor, List<?> methodComponents) {
        // Exactly one original construction, outside the observer exception boundary.
        ReloadableServerResources actualResources = ReloadableServerResourcesConstructorAccess.mmmm$createActual(
                constructorLoadResult, constructorFeatures, constructorSelection,
                constructorPendingTags, constructorPermissions, constructorComponents);
        if (constructorLoadResult != methodLoadResult || constructorFeatures != methodFeatures
                || constructorSelection != methodSelection || constructorPendingTags != methodPendingTags
                || constructorPermissions != methodPermissions || constructorComponents != methodComponents) return actualResources;
        try {
            var observation = NativeFunctionLoadObservation.forManager(actualManager);
            if (observation != null) observation.library(actualManager, actualResources, actualResources.getFunctionLibrary());
        } catch (RuntimeException | Error unavailable) {
            // Missing required library facts remain unavailable; preserve the native return.
        }
        return actualResources;
    }
}
