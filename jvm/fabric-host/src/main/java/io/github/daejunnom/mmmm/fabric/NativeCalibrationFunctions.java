package io.github.daejunnom.mmmm.fabric;

import com.mojang.brigadier.context.ContextChain;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.RedirectModifier;
import com.mojang.brigadier.arguments.ArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.tree.ArgumentCommandNode;
import java.lang.reflect.Method;
import io.github.daejunnom.mmmm.fabric.mixin.FunctionEntryReadAccess;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.IdentityHashMap;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.function.Predicate;
import net.minecraft.commands.execution.CustomCommandExecutor;
import net.minecraft.commands.execution.CustomModifierExecutor;
import net.minecraft.commands.execution.ChainModifiers;
import net.minecraft.commands.execution.ExecutionControl;
import net.minecraft.commands.execution.tasks.BuildContexts;
import net.minecraft.commands.functions.PlainTextFunction;
import net.minecraft.core.registries.Registries;
import net.minecraft.resources.FileToIdConverter;
import net.minecraft.resources.Identifier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.ServerFunctionLibrary;

/** Actual native constructor and selected-chain facts, without reparse, instantiate,
 * flatten, execution or SourceAdmission. ConstructorInputs remains a partial fact;
 * observeSelected additionally checks actual chains and current executable views. */
final class NativeCalibrationFunctions {
    static final int MAX_ENTRIES = 256;
    private static final int MAX_FUNCTION_KEYS = 4096;
    private NativeCalibrationFunctions() { }

    static final class SelectedStatement {
        private final ConstructorStatement constructor;
        private final List<CommandContext<?>> contexts;
        private final List<ContextChain<?>> chains;
        private final List<List<Object>> nodes;
        private final List<Integer> executableRefs;
        private final CommandContext<?> terminal;
        private final int rangeStart, rangeEnd;
        private SelectedStatement(ConstructorStatement constructor, List<CommandContext<?>> contexts, List<ContextChain<?>> chains,
                                  List<List<Object>> nodes, List<Integer> refs, int start, int end) {
            this.constructor = constructor; this.contexts = List.copyOf(contexts); this.chains = List.copyOf(chains); this.nodes = List.copyOf(nodes);
            executableRefs = List.copyOf(refs); terminal = contexts.getLast(); rangeStart = start; rangeEnd = end;
        }
        Object actualEntry() { return constructor.entry; }
        String originalInput() { return constructor.input; }
        CommandContext<?> terminal() { return terminal; }
        List<Integer> executableRefs() { return executableRefs; }
        int rangeStart() { return rangeStart; }
        int rangeEnd() { return rangeEnd; }
        boolean hasChain(Object actual) { return chains.stream().anyMatch(chain -> chain == actual); }
        boolean matchesTerminal(CommandContext<?> actual) {
            return actual.getRootNode() == terminal.getRootNode() && actual.getCommand() == terminal.getCommand()
                    && actual.getRedirectModifier() == terminal.getRedirectModifier()
                    && actual.getInput().equals(originalInput()) && actual.getRange().equals(terminal.getRange())
                    && sameObjects(actual.getNodes(), terminal.getNodes());
        }
    }
    /** Actual stored chains are read and validated without parsing again.
     * These current VM executable facts remain factual, not SourceAdmission. */
    static final class SelectedFunction {
        private final ConstructorInputs input;
        private final List<SelectedStatement> statements;
        private final NativeCalibrationExecutables.Witness executables;
        private SelectedFunction(ConstructorInputs input, List<SelectedStatement> statements,
                                 NativeCalibrationExecutables.Witness executables) {
            this.input = input; this.statements = List.copyOf(statements); this.executables = executables;
        }
        NativeLoadedCalibrationSources.LoadedFunction loadedFunction() { return input.loaded; }
        List<SelectedStatement> statements() { return statements; }
        NativeCalibrationExecutables.Witness executables() { return executables; }
        void reobserveSourceBytes(NativeCalibrationApproval.Control original) { input.reobserveSourceBytes(original); }
        void checkCurrent(NativeCalibrationApproval.Control original) {
            checked(() -> {
                input.checkCurrent(original);
                List<NativeCalibrationExecutables.Selection> selected = new ArrayList<>();
                for (int index = 0; index < statements.size(); index++) {
                    original.checkpoint();
                    SelectedStatement current = select(input.statements.get(index), selected, original);
                    SelectedStatement previous = statements.get(index);
                    if (current.terminal != previous.terminal || current.rangeStart != previous.rangeStart
                            || current.rangeEnd != previous.rangeEnd || !current.executableRefs.equals(previous.executableRefs)
                            || !sameObjects(current.contexts, previous.contexts) || !sameObjects(current.chains, previous.chains)
                            || current.nodes.size() != previous.nodes.size())
                        throw failure("CALIBRATION_FUNCTION_CHANGED");
                    for (int stage = 0; stage < current.nodes.size(); stage++)
                        if (!sameObjects(current.nodes.get(stage), previous.nodes.get(stage))) throw failure("CALIBRATION_FUNCTION_CHANGED");
                }
                if (selected.size() != executables.facts().size()) throw failure("CALIBRATION_FUNCTION_CHANGED");
                for (int index = 0; index < selected.size(); index++) {
                    original.checkpoint(); var actual = selected.get(index); var previous = executables.facts().get(index);
                    if (actual.actualReceiver() != previous.actualReceiver() || !actual.selectedMethod().equals(previous.selectedMethod())
                            || actual.role() != previous.role()) throw failure("CALIBRATION_FUNCTION_CHANGED");
                }
                executables.checkCurrent(original::checkpoint); input.checkCurrent(original); return null;
            }, original);
        }
    }

    static SelectedFunction observeSelected(MinecraftServer server, NativeCalibrationApproval.Program program,
                                            NativeCalibrationApproval.Control original) {
        return checked(() -> {
            ConstructorInputs input = observeConstructorInputs(server, program, original);
            List<NativeCalibrationExecutables.Selection> selected = new ArrayList<>();
            List<SelectedStatement> statements = new ArrayList<>();
            for (ConstructorStatement statement : input.statements) {
                original.checkpoint(); statements.add(select(statement, selected, original));
            }
            var executableFacts = NativeCalibrationExecutables.acquire(selected, original::checkpoint);
            var result = new SelectedFunction(input, statements, executableFacts);
            result.checkCurrent(original); return result;
        }, original);
    }

    private static SelectedStatement select(ConstructorStatement statement,
            List<NativeCalibrationExecutables.Selection> all, NativeCalibrationApproval.Control original) {
        var contexts = new ArrayList<CommandContext<?>>(); var chains = new ArrayList<ContextChain<?>>(); var nodes = new ArrayList<List<Object>>();
        var refs = new ArrayList<Integer>(); var visited = new IdentityHashMap<ContextChain<?>, Boolean>();
        ContextChain<?> chain = statement.chain; int first = -1, last = -1, count = 0;
        while (chain != null) {
            original.checkpoint();
            if (visited.put(chain, true) != null || contexts.size() >= MAX_ENTRIES) throw failure("CALIBRATION_CHAIN_LIMIT");
            CommandContext<?> context = chain.getTopContext();
            if (context == null || !statement.input.equals(context.getInput())) throw failure("CALIBRATION_CHAIN_INPUT_MISMATCH");
            int start = context.getRange().getStart(), end = context.getRange().getEnd();
            if (start < 0 || end < start || end > statement.input.length()
                    || !utf16Boundary(statement.input, start) || !utf16Boundary(statement.input, end)) throw failure("CALIBRATION_CHAIN_RANGE_MISMATCH");
            if (first < 0) first = start;
            var actualNodes = new ArrayList<Object>(); int previousEnd = start;
            for (var parsed : context.getNodes()) {
                original.checkpoint();
                if (++count > MAX_ENTRIES) throw failure("CALIBRATION_CHAIN_LIMIT");
                int nodeStart = parsed.getRange().getStart(), nodeEnd = parsed.getRange().getEnd();
                if (nodeStart < previousEnd || nodeEnd <= nodeStart || nodeEnd > end
                        || !utf16Boundary(statement.input, nodeStart) || !utf16Boundary(statement.input, nodeEnd))
                    throw failure("CALIBRATION_CHAIN_RANGE_MISMATCH");
                previousEnd = nodeEnd; actualNodes.add(parsed); var node = parsed.getNode();
                add(refs, all, node.getRequirement(), method(Predicate.class, "test", Object.class), NativeCalibrationExecutables.Role.PREDICATE);
                if (node instanceof ArgumentCommandNode<?, ?> argument) {
                    Object type = argument.getType();
                    add(refs, all, type, method(ArgumentType.class, "parse", StringReader.class, Object.class), NativeCalibrationExecutables.Role.PARSER);
                    // The observed default overload delegates to parse(reader).
                    if (method(type.getClass(), "parse", StringReader.class, Object.class).getDeclaringClass() == ArgumentType.class)
                        add(refs, all, type, method(ArgumentType.class, "parse", StringReader.class), NativeCalibrationExecutables.Role.PARSER);
                }
            }
            if (actualNodes.isEmpty() || previousEnd != end) throw failure("CALIBRATION_CHAIN_RANGE_MISMATCH");
            var lastNode = context.getNodes().getLast().getNode();
            if (lastNode.getCommand() != context.getCommand() || lastNode.getRedirectModifier() != context.getRedirectModifier())
                throw failure("CALIBRATION_SELECTED_NODE_CHANGED");
            contexts.add(context); chains.add(chain); nodes.add(List.copyOf(actualNodes));
            Object redirect = context.getRedirectModifier();
            if (redirect != null) {
                Method selected = CustomModifierExecutor.class.isInstance(redirect)
                    ? method(CustomModifierExecutor.class, "apply", Object.class, List.class, ContextChain.class, ChainModifiers.class, ExecutionControl.class)
                    : method(RedirectModifier.class, "apply", CommandContext.class);
                add(refs, all, redirect, selected, NativeCalibrationExecutables.Role.REDIRECT);
            }
            if (chain.getStage() == ContextChain.Stage.EXECUTE) {
                Object handler = context.getCommand();
                if (handler == null) throw failure("CALIBRATION_CHAIN_UNSUPPORTED");
                Method selected = CustomCommandExecutor.class.isInstance(handler)
                    ? method(CustomCommandExecutor.class, "run", Object.class, ContextChain.class, ChainModifiers.class, ExecutionControl.class)
                    : method(Command.class, "run", CommandContext.class);
                add(refs, all, handler, selected, NativeCalibrationExecutables.Role.HANDLER);
                last = end; break;
            }
            if (chain.getStage() != ContextChain.Stage.MODIFY) throw failure("CALIBRATION_CHAIN_UNSUPPORTED");
            chain = chain.nextStage();
        }
        if (first != 0 || last != statement.input.length()) throw failure("CALIBRATION_CHAIN_NOT_FULLY_CONSUMED");
        return new SelectedStatement(statement, contexts, chains, nodes, refs, first, last);
    }
    private static Method method(Class<?> owner, String name, Class<?>... parameters) {
        try { return owner.getMethod(name, parameters); }
        catch (NoSuchMethodException | SecurityException failure) {
            var wrapped = failure("CALIBRATION_SELECTED_METHOD_UNAVAILABLE"); wrapped.initCause(failure); throw wrapped;
        }
    }
    private static void add(List<Integer> refs, List<NativeCalibrationExecutables.Selection> all,
                            Object receiver, Method method, NativeCalibrationExecutables.Role role) {
        if (receiver == null) throw failure("CALIBRATION_SELECTED_METHOD_UNAVAILABLE");
        int index = 0;
        for (; index < all.size(); index++) {
            var previous = all.get(index);
            if (previous.actualReceiver() == receiver && previous.selectedMethod().equals(method) && previous.role() == role) break;
        }
        if (index == all.size()) {
            if (all.size() >= NativeCalibrationExecutables.MAX_SELECTIONS) throw failure("CALIBRATION_CHAIN_LIMIT");
            all.add(new NativeCalibrationExecutables.Selection(receiver, method, role));
        }
        if (!refs.contains(index)) refs.add(index);
    }
    private static boolean sameObjects(List<?> first, List<?> second) {
        if (first.size() != second.size()) return false;
        for (int index = 0; index < first.size(); index++) if (first.get(index) != second.get(index)) return false;
        return true;
    }
    private static boolean utf16Boundary(String input, int index) {
        return index <= 0 || index >= input.length() || !Character.isHighSurrogate(input.charAt(index - 1)) || !Character.isLowSurrogate(input.charAt(index));
    }

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
    static <T> T checked(Supplier<T> action, NativeCalibrationApproval.Control current) {
        return checked(action, current::checkpoint);
    }
    static <T> T checked(Supplier<T> action, Runnable current) {
        current.run(); Throwable primary = null;
        try { return action.get(); }
        catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            try { current.run(); }
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
