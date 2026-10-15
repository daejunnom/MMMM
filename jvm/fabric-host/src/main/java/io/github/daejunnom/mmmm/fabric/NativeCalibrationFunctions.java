package io.github.daejunnom.mmmm.fabric;

import com.mojang.brigadier.context.ContextChain;
import io.github.daejunnom.mmmm.fabric.mixin.FunctionEntryReadAccess;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import net.minecraft.commands.execution.tasks.BuildContexts;
import net.minecraft.commands.functions.PlainTextFunction;
import net.minecraft.core.registries.Registries;
import net.minecraft.resources.FileToIdConverter;
import net.minecraft.resources.Identifier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.ServerFunctionLibrary;

/** Partial facts about actual native constructor inputs and chain references.
 * This does not validate a chain's input, full consumption, selected nodes or
 * current parser/handler/predicate identity. Those require a later observer.
 * No parse, instantiate, flatten, execution, SourceAdmission or authority lives here. */
final class NativeCalibrationFunctions {
    static final int MAX_ENTRIES = 256;
    private static final int MAX_FUNCTION_KEYS = 4096;
    private NativeCalibrationFunctions() { }

    static final class ConstructorStatement {
        private final Object entry;
        private final String input;
        private final ContextChain<?> chain;
        private ConstructorStatement(Object entry, String input, ContextChain<?> chain) {
            this.entry = entry; this.input = input; this.chain = chain;
        }
        Object actualEntry() { return entry; }
        String originalInput() { return input; }
        ContextChain<?> compiledChainReference() { return chain; }
    }

    /** Only observeConstructorInputs() issues this partial constructor fact.
     * Matching raw input and nonnull chain do not prove that the chain parsed
     * that input or consumed it fully. This cannot admit a parser or execution.
     * It retains no request/control callback and has no RawFacts/JSON factory. */
    static final class ConstructorInputs {
        private final MinecraftServer server;
        private final NativeLoadedCalibrationSources.ExpectedSource<Identifier> expected;
        private final NativeLoadedCalibrationSources.ObservedSources sources;
        private final NativeLoadedCalibrationSources.LoadedFunction loaded;
        private final List<ConstructorStatement> statements;
        private ConstructorInputs(MinecraftServer server, NativeLoadedCalibrationSources.ExpectedSource<Identifier> expected,
                        NativeLoadedCalibrationSources.ObservedSources sources,
                        NativeLoadedCalibrationSources.LoadedFunction loaded, List<ConstructorStatement> statements) {
            this.server = server; this.expected = expected; this.sources = sources;
            this.loaded = loaded; this.statements = List.copyOf(statements);
        }
        NativeLoadedCalibrationSources.LoadedFunction loadedFunction() { return loaded; }
        List<ConstructorStatement> statements() { return statements; }
        /** Object/manager/winner currentness only; it does not re-read source bytes. */
        void checkCurrent(NativeCalibrationApproval.Control original) {
            checked(() -> {
                sources.checkCurrent(original::checkpoint);
                List<?> actual = entries(loaded);
                if (actual.size() != statements.size()) throw failure("CALIBRATION_FUNCTION_CHANGED");
                for (int index = 0; index < actual.size(); index++) {
                    original.checkpoint();
                    ConstructorStatement expected = statements.get(index);
                    if (actual.get(index) != expected.entry || !(expected.entry instanceof FunctionEntryReadAccess read)
                            || !expected.input.equals(read.mmmm$originalCommandInput())
                            || read.mmmm$compiledContextChain() != expected.chain) throw failure("CALIBRATION_FUNCTION_CHANGED");
                }
                sources.checkCurrent(original::checkpoint);
                return null;
            }, original);
        }
        /** Reuses the original bounded two-pass byte comparison, not manager
         * identity as a substitute for current file-input observations. */
        void reobserveSourceBytes(NativeCalibrationApproval.Control original) {
            checked(() -> {
                checkCurrent(original);
                var current = NativeLoadedCalibrationSources.observe(server, List.of(expected), original::checkpoint);
                var function = current.functions().getFirst();
                if (function.function() != loaded.function() || !function.sha256().equals(loaded.sha256())
                        || !function.sourcePackId().equals(loaded.sourcePackId())) throw failure("CALIBRATION_FUNCTION_CHANGED");
                checkCurrent(original);
                return null;
            }, original);
        }
    }

    static ConstructorInputs observeConstructorInputs(MinecraftServer server, NativeCalibrationApproval.Program program,
                           NativeCalibrationApproval.Control original) {
        Objects.requireNonNull(server); Objects.requireNonNull(program); Objects.requireNonNull(original);
        return checked(() -> {
            if (!server.isSameThread()) throw failure("CALIBRATION_SOURCE_THREAD_REQUIRED");
            var manager = server.getFunctions();
            int count = 0;
            for (Identifier id : manager.getFunctionNames()) {
                original.checkpoint();
                if (++count > MAX_FUNCTION_KEYS) throw failure("CALIBRATION_FUNCTION_LIMIT");
                if (program.functionId().equals(id.toString())) {
                    if (server.getFunctions() != manager) throw failure("CALIBRATION_FUNCTION_CHANGED");
                    var converter = new FileToIdConverter(Registries.elementsDirPath(ServerFunctionLibrary.TYPE_KEY), ".mcfunction");
                    var expected = new NativeLoadedCalibrationSources.ExpectedSource<>(id, converter.idToFile(id), program.sourceBytes());
                    return observeConstructorInputs(server, program, expected, original);
                }
            }
            throw failure("CALIBRATION_FUNCTION_UNAVAILABLE");
        }, original);
    }

    private static ConstructorInputs observeConstructorInputs(MinecraftServer server, NativeCalibrationApproval.Program program,
                           NativeLoadedCalibrationSources.ExpectedSource<Identifier> expected,
                           NativeCalibrationApproval.Control original) {
        Objects.requireNonNull(server); Objects.requireNonNull(program); Objects.requireNonNull(expected); Objects.requireNonNull(original);
        return checked(() -> {
            if (!program.functionId().equals(expected.functionId().toString())
                    || !Arrays.equals(program.sourceBytes(), expected.bytes())
                    || !program.sourceSha256().equals(ContractJson.sha256(expected.bytes()))) throw failure("CALIBRATION_FUNCTION_MISMATCH");
            var sources = NativeLoadedCalibrationSources.observe(server, List.of(expected), original::checkpoint);
            var loaded = sources.functions().getFirst();
            List<?> entries = entries(loaded);
            if (entries.isEmpty() || entries.size() > MAX_ENTRIES || entries.size() != program.commands().size())
                throw failure("CALIBRATION_FUNCTION_LIMIT");
            List<ConstructorStatement> statements = new ArrayList<>(entries.size());
            for (int index = 0; index < entries.size(); index++) {
                original.checkpoint(); Object entry = entries.get(index);
                if (entry == null || entry.getClass() != BuildContexts.Unbound.class || !(entry instanceof FunctionEntryReadAccess read)
                        || read.mmmm$compiledContextChain() == null
                        || !program.commands().get(index).equals(read.mmmm$originalCommandInput())) throw failure("CALIBRATION_FUNCTION_MISMATCH");
                statements.add(new ConstructorStatement(entry, read.mmmm$originalCommandInput(), read.mmmm$compiledContextChain()));
            }
            ConstructorInputs witness = new ConstructorInputs(server, expected, sources, loaded, statements);
            witness.checkCurrent(original);
            return witness;
        }, original);
    }

    private static List<?> entries(NativeLoadedCalibrationSources.LoadedFunction loaded) {
        // Macro instantiation and arbitrary CommandFunction implementations are
        // not read adapters. The actual native PlainTextFunction returns its entries.
        if (loaded.function().getClass() != PlainTextFunction.class) throw failure("CALIBRATION_FUNCTION_UNSUPPORTED");
        PlainTextFunction<?> plain = (PlainTextFunction<?>) loaded.function();
        List<?> entries = plain.entries();
        if (entries == null || entries.size() > MAX_ENTRIES) throw failure("CALIBRATION_FUNCTION_LIMIT");
        return entries;
    }
    private static <T> T checked(Supplier<T> action, NativeCalibrationApproval.Control current) {
        current.checkpoint(); Throwable primary = null;
        try { return action.get(); }
        catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            try { current.checkpoint(); }
            catch (RuntimeException | Error post) {
                if (primary == null) throw post;
                if (post != primary) primary.addSuppressed(post);
            }
        }
    }
    private static ContractException failure(String code) {
        return new ContractException(code, "Actual loaded calibration function entries are unavailable or changed");
    }
}
