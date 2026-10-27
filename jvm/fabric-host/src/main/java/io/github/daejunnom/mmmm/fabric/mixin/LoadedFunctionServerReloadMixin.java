package io.github.daejunnom.mmmm.fabric.mixin;

import com.google.common.collect.ImmutableList;
import io.github.daejunnom.mmmm.fabric.NativeFunctionLoadHookContexts;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.packs.PackResources;
import net.minecraft.server.packs.PackType;
import net.minecraft.server.packs.resources.MultiPackResourceManager;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/** Exact 26.3 outer reload callsites; inner component reload uses no outer observer phases. */
@Mixin(MinecraftServer.class)
public abstract class LoadedFunctionServerReloadMixin {
    @Redirect(method = "reloadResources(Ljava/util/Collection;)Ljava/util/concurrent/CompletableFuture;",
        at = @At(value = "INVOKE", target = "Ljava/util/concurrent/CompletableFuture;supplyAsync(Ljava/util/function/Supplier;Ljava/util/concurrent/Executor;)Ljava/util/concurrent/CompletableFuture;"), require = 1, expect = 1, allow = 1)
    private CompletableFuture<?> mmmm$observeOpenedPacks(Supplier<?> original, Executor actualExecutor,
            Collection<String> actualSelection) {
        return NativeFunctionLoadHookContexts.supplyAsync(this, actualSelection, original, actualExecutor);
    }

    @Redirect(method = "reloadResources(Ljava/util/Collection;)Ljava/util/concurrent/CompletableFuture;",
        at = @At(value = "INVOKE", target = "Ljava/util/concurrent/CompletableFuture;thenCompose(Ljava/util/function/Function;)Ljava/util/concurrent/CompletableFuture;"), require = 1, expect = 1, allow = 1)
    private CompletableFuture<?> mmmm$observeManagerContinuation(CompletableFuture<?> actualPriorFuture,
            Function<?, ?> original, Collection<String> actualSelection) {
        return NativeFunctionLoadHookContexts.thenCompose(this, actualSelection, actualPriorFuture, original);
    }

    @Redirect(method = "reloadResources(Ljava/util/Collection;)Ljava/util/concurrent/CompletableFuture;",
        at = @At(value = "INVOKE", target = "Ljava/util/concurrent/CompletableFuture;thenAcceptAsync(Ljava/util/function/Consumer;Ljava/util/concurrent/Executor;)Ljava/util/concurrent/CompletableFuture;"), require = 1, expect = 1, allow = 1)
    private CompletableFuture<Void> mmmm$observeResourcePublication(CompletableFuture<?> actualPriorFuture,
            Consumer<?> original, Executor actualExecutor, Collection<String> actualSelection) {
        return NativeFunctionLoadHookContexts.thenAcceptAsync(this, actualSelection, actualPriorFuture, original, actualExecutor);
    }

    @Redirect(method = "lambda$reloadResources$1(Lcom/google/common/collect/ImmutableList;)Ljava/util/concurrent/CompletionStage;",
        at = @At(value = "NEW", target = "(Lnet/minecraft/server/packs/PackType;Ljava/util/List;)Lnet/minecraft/server/packs/resources/MultiPackResourceManager;"), require = 1, expect = 1, allow = 1)
    private MultiPackResourceManager mmmm$observeActualManager(PackType actualType, List<PackResources> actualPacks,
            ImmutableList<PackResources> actualOpenedList) {
        // The actual constructor runs once. Its exception and native ownership stay unchanged.
        var actualManager = new MultiPackResourceManager(actualType, actualPacks);
        if (actualPacks == actualOpenedList) {
            NativeFunctionLoadHookContexts.managerCreated(this, actualOpenedList, actualManager);
        }
        return actualManager;
    }

    @Redirect(method = "reloadResources(Ljava/util/Collection;)Ljava/util/concurrent/CompletableFuture;",
        at = @At(value = "INVOKE", target = "Lnet/minecraft/server/MinecraftServer;isSameThread()Z"), require = 1, expect = 1, allow = 1)
    private boolean mmmm$observeReturnThreadCheck(MinecraftServer actualServer, Collection<String> actualSelection) {
        boolean returned = false;
        try {
            boolean actualResult = actualServer.isSameThread();
            returned = true;
            return actualResult;
        } finally {
            if (!returned) NativeFunctionLoadHookContexts.failedBeforeReturn(actualServer, actualSelection);
        }
    }

    @Redirect(method = "reloadResources(Ljava/util/Collection;)Ljava/util/concurrent/CompletableFuture;",
        at = @At(value = "INVOKE", target = "Lnet/minecraft/server/MinecraftServer;managedBlock(Ljava/util/function/BooleanSupplier;)V"), require = 1, expect = 1, allow = 1)
    private void mmmm$observeReturnBlock(MinecraftServer actualServer, BooleanSupplier actualCompletion,
            Collection<String> actualSelection) {
        boolean returned = false;
        try {
            actualServer.managedBlock(actualCompletion);
            returned = true;
        } finally {
            if (!returned) NativeFunctionLoadHookContexts.failedBeforeReturn(actualServer, actualSelection);
        }
    }

    @Inject(method = "reloadResources(Ljava/util/Collection;)Ljava/util/concurrent/CompletableFuture;", at = @At("RETURN"), require = 1, expect = 1, allow = 1)
    private void mmmm$observeOriginalReturn(Collection<String> actualSelection,
            CallbackInfoReturnable<CompletableFuture<Void>> callback) {
        NativeFunctionLoadHookContexts.returned(this, actualSelection, callback.getReturnValue());
    }
}
