package io.github.daejunnom.mmmm.fabric.mixin;

import com.mojang.brigadier.CommandDispatcher;
import io.github.daejunnom.mmmm.fabric.NativeFunctionLoadEntryContexts;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.ExecutionCommandSource;
import net.minecraft.commands.functions.CommandFunction;
import net.minecraft.resources.FileToIdConverter;
import net.minecraft.resources.Identifier;
import net.minecraft.server.ServerFunctionLibrary;
import net.minecraft.server.packs.resources.Resource;
import org.objectweb.asm.Opcodes;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/** Actual loader arguments and returns only; Rust selects the observed function set. */
@Mixin(ServerFunctionLibrary.class)
public abstract class LoadedFunctionLibraryMixin {
    @Shadow private volatile Map<Identifier, CommandFunction<CommandSourceStack>> functions;

    @Shadow
    private static List<String> readLines(Resource actualResource) {
        throw new AssertionError("The actual native resource reader shadow was not transformed");
    }

    @Redirect(method = "reload(Lnet/minecraft/server/packs/resources/PreparableReloadListener$SharedState;"
            + "Ljava/util/concurrent/Executor;Lnet/minecraft/server/packs/resources/PreparableReloadListener$PreparationBarrier;"
            + "Ljava/util/concurrent/Executor;)Ljava/util/concurrent/CompletableFuture;",
            at = @At(value = "INVOKE", target = "Ljava/util/concurrent/CompletableFuture;thenCompose("
                    + "Ljava/util/function/Function;)Ljava/util/concurrent/CompletableFuture;", ordinal = 0),
            require = 1, expect = 1, allow = 1)
    private CompletableFuture<?> mmmm$observePreparation(CompletableFuture<?> actualPriorFuture,
            Function<?, ?> actualOriginalFunction) {
        return NativeFunctionLoadEntryContexts.prepareThenCompose(this, actualPriorFuture, actualOriginalFunction);
    }

    @Redirect(method = "lambda$reload$2(Ljava/util/concurrent/Executor;Ljava/util/Map;)Ljava/util/concurrent/CompletionStage;",
            at = @At(value = "INVOKE", target = "Ljava/util/Iterator;next()Ljava/lang/Object;"),
            require = 1, expect = 1, allow = 1)
    private Object mmmm$observeEntry(Iterator<?> actualIterator) {
        Object actualEntry = actualIterator.next();
        return NativeFunctionLoadEntryContexts.entryReturned(this, actualIterator, actualEntry);
    }

    @Redirect(method = "lambda$reload$2(Ljava/util/concurrent/Executor;Ljava/util/Map;)Ljava/util/concurrent/CompletionStage;",
            at = @At(value = "INVOKE", target = "Ljava/util/Map$Entry;getKey()Ljava/lang/Object;"),
            require = 1, expect = 1, allow = 1)
    private Object mmmm$observeResourceIdentifier(Map.Entry<?, ?> actualEntry) {
        Object actualResourceIdentifier = actualEntry.getKey();
        return NativeFunctionLoadEntryContexts.resourceKeyReturned(this, actualEntry, actualResourceIdentifier);
    }

    @Redirect(method = "lambda$reload$2(Ljava/util/concurrent/Executor;Ljava/util/Map;)Ljava/util/concurrent/CompletionStage;",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/resources/FileToIdConverter;fileToId("
                    + "Lnet/minecraft/resources/Identifier;)Lnet/minecraft/resources/Identifier;"),
            require = 1, expect = 1, allow = 1)
    private Identifier mmmm$observeFunctionIdentifier(FileToIdConverter actualLister, Identifier actualResourceIdentifier) {
        Identifier actualFunctionIdentifier = actualLister.fileToId(actualResourceIdentifier);
        return NativeFunctionLoadEntryContexts.functionIdReturned(this, actualLister, actualResourceIdentifier, actualFunctionIdentifier);
    }

    @Redirect(method = "lambda$reload$2(Ljava/util/concurrent/Executor;Ljava/util/Map;)Ljava/util/concurrent/CompletionStage;",
            at = @At(value = "INVOKE", target = "Ljava/util/concurrent/CompletableFuture;supplyAsync("
                    + "Ljava/util/function/Supplier;Ljava/util/concurrent/Executor;)Ljava/util/concurrent/CompletableFuture;"),
            require = 1, expect = 1, allow = 1)
    private CompletableFuture<?> mmmm$observeEntrySupplier(Supplier<?> actualOriginalSupplier, Executor actualExecutor) {
        return NativeFunctionLoadEntryContexts.supplyAsyncEntry(this, actualOriginalSupplier, actualExecutor);
    }

    @Redirect(method = "lambda$reload$3(Ljava/util/Map$Entry;Lnet/minecraft/resources/Identifier;"
            + "Lnet/minecraft/commands/CommandSourceStack;)Lnet/minecraft/commands/functions/CommandFunction;",
            at = @At(value = "INVOKE", target = "Ljava/util/Map$Entry;getValue()Ljava/lang/Object;"),
            require = 1, expect = 1, allow = 1)
    private Object mmmm$observeResource(Map.Entry<?, ?> actualReceiver, Map.Entry<?, ?> actualEntry,
            Identifier actualFunctionIdentifier, CommandSourceStack actualCompilationSource) {
        Object actualResource = actualReceiver.getValue();
        if (actualReceiver != actualEntry) return actualResource;
        return NativeFunctionLoadEntryContexts.resourceReturned(this, actualEntry, actualFunctionIdentifier, actualResource);
    }

    @Redirect(method = "lambda$reload$3(Ljava/util/Map$Entry;Lnet/minecraft/resources/Identifier;"
            + "Lnet/minecraft/commands/CommandSourceStack;)Lnet/minecraft/commands/functions/CommandFunction;",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/server/ServerFunctionLibrary;readLines("
                    + "Lnet/minecraft/server/packs/resources/Resource;)Ljava/util/List;"),
            require = 1, expect = 1, allow = 1)
    private List<String> mmmm$observeReadLines(Resource actualResource) {
        List<String> actualLines;
        try {
            actualLines = readLines(actualResource);
        } catch (RuntimeException | Error actualFailure) {
            NativeFunctionLoadEntryContexts.readLinesFailed(actualResource, actualFailure);
            throw actualFailure;
        }
        return NativeFunctionLoadEntryContexts.readLinesReturned(actualResource, actualLines);
    }

    @Redirect(method = "lambda$reload$3(Ljava/util/Map$Entry;Lnet/minecraft/resources/Identifier;"
            + "Lnet/minecraft/commands/CommandSourceStack;)Lnet/minecraft/commands/functions/CommandFunction;",
            at = @At(value = "INVOKE", target = "Lnet/minecraft/commands/functions/CommandFunction;fromLines("
                    + "Lnet/minecraft/resources/Identifier;Lcom/mojang/brigadier/CommandDispatcher;"
                    + "Lnet/minecraft/commands/ExecutionCommandSource;Ljava/util/List;)Lnet/minecraft/commands/functions/CommandFunction;"),
            require = 1, expect = 1, allow = 1)
    private <T extends ExecutionCommandSource<T>> CommandFunction<T> mmmm$observeCompiledFunction(
            Identifier actualFunctionIdentifier, CommandDispatcher<T> actualDispatcher, T actualSource,
            List<String> actualLines, Map.Entry<?, ?> actualEntry, Identifier methodFunctionIdentifier,
            CommandSourceStack methodCompilationSource) {
        boolean sameArguments = actualFunctionIdentifier == methodFunctionIdentifier && (Object) actualSource == methodCompilationSource;
        CommandFunction<T> actualFunction;
        try {
            actualFunction = CommandFunction.fromLines(actualFunctionIdentifier, actualDispatcher, actualSource, actualLines);
        } catch (RuntimeException | Error actualFailure) {
            if (sameArguments) NativeFunctionLoadEntryContexts.fromLinesFailed(this, actualEntry, actualFunctionIdentifier, actualLines, actualFailure);
            throw actualFailure;
        }
        return sameArguments
                ? NativeFunctionLoadEntryContexts.fromLinesReturned(this, actualEntry, actualFunctionIdentifier, actualLines, actualFunction)
                : actualFunction;
    }

    @Redirect(method = "lambda$reload$5(Lcom/mojang/datafixers/util/Pair;)V",
            at = @At(value = "FIELD", target = "Lnet/minecraft/server/ServerFunctionLibrary;functions:Ljava/util/Map;",
                    opcode = Opcodes.PUTFIELD), require = 1, expect = 1, allow = 1)
    private void mmmm$observePublishedFunctions(ServerFunctionLibrary actualOwner,
            Map<Identifier, CommandFunction<CommandSourceStack>> actualMap) {
        // Mixin rewrites this self type to the actual target. Perform the original volatile
        // field store once, then relay its operand rather than a subsequent racy field read.
        ((LoadedFunctionLibraryMixin) (Object) actualOwner).functions = actualMap;
        NativeFunctionLoadEntryContexts.functionsStored(actualOwner, actualMap);
    }
}
