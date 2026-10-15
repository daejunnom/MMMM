package io.github.daejunnom.mmmm.fabric;

import com.mojang.brigadier.ParseResults;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.fabric.mixin.CommandsContextReadAccess;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.Objects;
import java.util.ArrayList;
import java.util.List;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.MinecraftServer;

/** Uses the game's bounded command queue and a single invocation-local native result callback. */
final class NativeCommandDispatch {
    private NativeCommandDispatch() { }

    static void requireIdle(MinecraftServer server) {
        if (server == null || !server.isSameThread()) {
            throw new ContractException("GAME_THREAD_REQUIRED", "Native command admission requires the current server thread");
        }
        try {
            if (CommandsContextReadAccess.mmmm$currentExecutionContext().get() != null) {
                // executeCommandInContext queues onto an existing context without draining it. That
                // would permit effects after MMMM's scope and callback have ended.
                throw new ContractException("NATIVE_COMMAND_REENTRANT", "Native command dispatch cannot join an existing game execution context");
            }
        } catch (LinkageError | AssertionError exception) {
            throw new ContractException("NATIVE_READ_ACCESS_UNAVAILABLE", "The exact native command read accessor is unavailable");
        }
    }

    static int execute(MinecraftServer server, ParseResults<CommandSourceStack> parsed) throws CommandSyntaxException {
        return perform(server, parsed).single();
    }

    /** Same native function queue, with actual optional callback facts. Completion is
     * established separately by the private runner's entry/queue hooks, never by zero synthesis. */
    static Observation executeObserved(MinecraftServer server, ParseResults<CommandSourceStack> parsed) throws CommandSyntaxException {
        return perform(server, parsed).observation();
    }
    record Callback(boolean success, int returned) { }
    static final class Observation {
        private final List<Callback> callbacks;
        private Observation(List<Callback> callbacks) { this.callbacks = List.copyOf(callbacks); }
        int callbackCount() { return callbacks.size(); }
        Integer singleReturn() { return callbacks.size() == 1 ? callbacks.getFirst().returned() : null; }
        List<Callback> callbacks() { return callbacks; }
    }
    private static Result perform(MinecraftServer server, ParseResults<CommandSourceStack> parsed) throws CommandSyntaxException {
        Objects.requireNonNull(parsed); requireIdle(server);
        CommandSourceStack original = parsed.getContext().getSource();
        if (original == null || original.getServer() != server || original.getLevel().getServer() != server) {
            throw new ContractException("SESSION_EPOCH_MISMATCH", "The parsed native source belongs to another server");
        }
        if (parsed.getReader().canRead() || !parsed.getExceptions().isEmpty()) {
            Commands.validateParseResults(parsed);
            throw new ContractException("NATIVE_PARSE_INCOMPLETE", "Native command parsing did not consume the entire original source");
        }
        Commands.validateParseResults(parsed);
        Result result = new Result(server);
        var withResult = Commands.mapSource(parsed, source -> source.withSuppressedOutput().withCallback(result::accept));
        try {
            // performCommand constructs and drains the real native ExecutionContext, with the
            // server's command/fork limits. No global dispatcher consumer is changed here.
            requireIdle(server);
            server.getCommands().performCommand(withResult, parsed.getReader().getString());
        } finally {
            result.close();
        }
        requireIdle(server);
        return result;
    }

    private static final class Result {
        private final MinecraftServer server;
        private boolean active = true;
        private boolean invalid;
        private int count;
        private int value;
        private final List<Callback> callbacks = new ArrayList<>();

        private Result(MinecraftServer server) { this.server = server; }
        private synchronized void accept(boolean success, int returned) {
            if (!active || !server.isSameThread()) { invalid = true; return; }
            if (invalid) return;
            if (count == 256 || !success && returned != 0) { invalid = true; return; }
            count++;
            callbacks.add(new Callback(success, returned));
            value = returned;
        }
        private synchronized void close() { active = false; }
        private synchronized int single() {
            if (invalid || count != 1) {
                throw new ContractException("NATIVE_RETURN_UNCONFIRMED", "Native execution did not produce exactly one synchronous result callback");
            }
            return value;
        }
        private synchronized Observation observation() {
            if (invalid) throw new ContractException("NATIVE_RETURN_UNCONFIRMED", "Native callback observation exceeded its bound or owner");
            return new Observation(callbacks);
        }
    }
}
