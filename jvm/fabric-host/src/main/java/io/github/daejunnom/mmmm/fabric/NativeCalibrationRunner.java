package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.context.ContextChain;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;

/** One original native function invocation, preserving the game's own function queue.
 * No initialization, reload, cleanup, source reparse or command-by-command substitute. */
final class NativeCalibrationRunner implements NativeCalibrationApproval.Runner, AutoCloseable {
    private static final int MAX_RUNS = 47, MAX_EVENTS = 4096;
    // Aggregate historical facts only. Per-record 1MiB transport and executable
    // witness 64-class/8MiB limits remain unchanged; charge both wire and VM bytes.
    private static final long MAX_RETAINED_BYTES = 64L * 1024 * 1024;
    record Pins(ObjectNode environment, String sourceFactsDigest, String hostDigest, String generation) {
        Pins { environment = environment.deepCopy(); }
        @Override public ObjectNode environment() { return environment.deepCopy(); }
        ObjectNode envelope(ObjectNode context) {
            ObjectNode result = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION)
                    .put("contextId", context.path("contextId").asText()).put("contextDigest", context.path("contextDigest").asText())
                    .put("runtimeSourceFactsDigest", sourceFactsDigest).put("hostArtifactDigest", hostDigest).put("registryGeneration", generation);
            result.set("environment", environment()); return result;
        }
    }
    /** Only execute's complete native observation path can construct this token. */
    static final class CompletedRun {
        private final NativeCalibrationRunner owner;
        private final Invocation original;
        private final NativeCalibrationApproval.Program program;
        private final Trace trace;
        private final NativeCalibrationTargetImages.ImagePair after;
        private final NativeCommandDispatch.Observation callbacks;
        private final long to;
        private final String at;
        private CompletedRun(NativeCalibrationRunner owner, Invocation original, NativeCalibrationApproval.Program program,
                             Trace trace, NativeCalibrationTargetImages.ImagePair after, NativeCommandDispatch.Observation callbacks) {
            this.owner = owner; this.original = original; this.program = program; this.trace = trace; this.after = after;
            this.callbacks = callbacks; to = owner.tick(); at = Instant.now().toString();
        }
        Invocation original() { return original; } NativeCalibrationApproval.Program program() { return program; }
        Pins pins() { return owner.pins; } NativeCalibrationFunctions.SelectedFunction function() { return trace.function; }
        List<NativeCalibrationRunFacts.CommandFact> commands() { return trace.snapshot(); }
        NativeCalibrationTargetImages.ImagePair preseed() { return trace.preseed; }
        NativeCalibrationTargetImages.ImagePair after() { return after; }
        NativeCommandDispatch.Observation callbacks() { return callbacks; }
        long from() { return trace.from; } long to() { return to; } String observedAt() { return at; }
    }
    /** Failure evidence only. It cannot be decoded/converted to a completed run or a ready grant. */
    static final class InterruptedTrace extends RuntimeException {
        private static final long serialVersionUID = 1L;
        // Process-local native identities and observations are not Java serialization data.
        private final transient List<NativeCalibrationRunFacts.CommandFact> observed;
        private final transient NativeCalibrationTargetImages.ImagePair preseed;
        private final transient NativeCalibrationExecutables.Witness executables;
        private final transient List<Throwable> nativeFailures;
        private InterruptedTrace(Trace trace) {
            super("Native calibration stopped with partial observations"); observed = trace.snapshot();
            preseed = trace.preseed; executables = trace.function.executables(); nativeFailures = List.copyOf(trace.nativeFailures);
        }
        List<NativeCalibrationRunFacts.CommandFact> observed() { return observed; }
        NativeCalibrationTargetImages.ImagePair preseed() { return preseed; }
        NativeCalibrationExecutables.Witness executables() { return executables; }
        List<Throwable> nativeFailures() { return nativeFailures; }
    }
    private final ContractJson contracts;
    private final MinecraftServer server;
    private final HostSession owner;
    private final Supplier<ServerPlayer> player;
    private final Function<String, ServerLevel> level;
    private final Pins pins;
    private final Map<String, NativeCalibrationRunFacts> runs = new ConcurrentHashMap<>();
    private final Map<String, String> started = new ConcurrentHashMap<>();
    private volatile NativeCalibrationPrepared prepared;
    private volatile long retained;
    private volatile boolean closed;

    NativeCalibrationRunner(ContractJson contracts, MinecraftServer server, HostSession owner, Supplier<ServerPlayer> player,
                            Function<String, ServerLevel> level, Pins pins) {
        this.contracts = Objects.requireNonNull(contracts); this.server = Objects.requireNonNull(server);
        this.owner = Objects.requireNonNull(owner); this.player = Objects.requireNonNull(player);
        this.level = Objects.requireNonNull(level); this.pins = Objects.requireNonNull(pins);
    }
    private void current(Invocation original, NativeCalibrationApproval.Control control) {
        control.checkpoint(); owner.checkOpen();
        if (closed || !server.isSameThread() || !original.context().equals(owner.context(original.contextId()))
                || !pins.environment().equals(original.context().get("environment"))) throw failure("CALIBRATION_RUN_SOURCE_STALE");
        control.checkpoint();
    }
    @Override public NativeCalibrationPrepared ready(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
        return NativeCalibrationFunctions.checked(() -> {
            current(original, control); NativeCommandDispatch.requireIdle(server);
            var observed = NativeCalibrationPrepared.observe(server, actualLevel(original), owner, pins, original, program, control);
            NativeCalibrationRunFacts.requireMetadataFits(original, program, pins, observed.function(), observed.images(), control);
            long reserve = observed.function().executables().retainedPayloadBytes() + 1024L * 1024
                    + 2L * NativeCalibrationTargetImages.MAX_PAIR_BYTES + 2L * program.sourceBytes().length
                    + MAX_EVENTS * 96L + 256L * 256;
            if (reserve > MAX_RETAINED_BYTES - retained)
                throw failure("CALIBRATION_RUN_SOURCE_LIMIT");
            // One read-only preparation is retained; replacing it creates no Accepted identity.
            current(original, control);
            synchronized (this) {
                if (closed) throw failure("CALIBRATION_RUN_SOURCE_STALE");
                prepared = observed;
            }
            return observed;
        }, control);
    }
    @Override public CompletionStage<ProviderResult> execute(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationApproval.Control control) {
        var result = new CompletableFuture<ProviderResult>(); Trace trace = null;
        try {
            current(original, control); var admitted = prepared;
            if (admitted == null) throw failure("CALIBRATION_PREPARATION_MISSING");
            admitted.checkCurrent(original, program, control);
            String originalDigest = ContractJson.digest(original.wire());
            synchronized (this) {
                if (closed) throw failure("CALIBRATION_RUN_SOURCE_STALE");
                if (started.size() >= MAX_RUNS || started.putIfAbsent(original.invocationId(), originalDigest) != null)
                    throw failure("CALIBRATION_RUN_ALREADY_STARTED");
                prepared = null;
            }
            var actualPlayer = player.get(); var actualLevel = actualLevel(original);
            if (actualPlayer == null || actualPlayer.level() != actualLevel)
                throw failure("CALIBRATION_RUN_SOURCE_STALE");
            NativeCommandDispatch.requireIdle(server);
            var source = NativeCommands.source(actualPlayer, actualLevel, original.context());
            var parsed = server.getCommands().getDispatcher().parse(new StringReader(program.command()), source);
            trace = new Trace(original, program, admitted.function(), actualLevel, parsed.getContext().build(program.command()).getCommand());
            NativeCommandDispatch.Observation returned;
            var scope = NativeCalibrationStageHooks.open(trace);
            try (scope) {
                current(original, control); trace.control = control;
                try { returned = NativeCommandDispatch.executeObserved(server, parsed); }
                finally { trace.control = null; }
            }
            trace.requireComplete(control);
            admitted.function().checkCurrent(control); admitted.function().reobserveSourceBytes(control);
            var after = NativeCalibrationTargetImages.observe(server, actualLevel, owner, original.context(), program, control);
            if (!after.objectiveFullTargetKnown() || !after.storageFullTargetKnown()) throw failure("CALIBRATION_AFTER_INCOMPLETE");
            current(original, control);
            var facts = NativeCalibrationRunFacts.completed(new CompletedRun(this, original, program, trace, after, returned), control);
            long bytes = facts.retainedBytes();
            if (bytes > MAX_RETAINED_BYTES - retained) throw failure("CALIBRATION_RUN_SOURCE_LIMIT");
            current(original, control);
            synchronized (this) {
                if (closed) throw failure("CALIBRATION_RUN_SOURCE_STALE");
                runs.put(original.invocationId(), facts); retained += bytes;
            }
            ObjectNode output = ContractJson.newObject().put("completionClaim", "native_function_queue_observed")
                    .put("nativeCallbackCount", returned.callbackCount());
            if (returned.singleReturn() == null) output.putNull("nativeCallbackReturn"); else output.put("nativeCallbackReturn", returned.singleReturn());
            result.complete(ProviderResult.complete(contracts, output, "unknown"));
        } catch (CommandSyntaxException | RuntimeException | Error primary) {
            Throwable terminal = trace == null || trace.boundaryFailure == null ? primary : trace.boundaryFailure;
            preserve(terminal, primary);
            if (trace != null) preserve(terminal, new InterruptedTrace(trace));
            try { current(original, control); } catch (RuntimeException | Error post) { preserve(terminal, post); }
            result.completeExceptionally(terminal);
        }
        return result.minimalCompletionStage();
    }
    @Override public CompletionStage<ObjectNode> poll(Invocation original, NativeCalibrationApproval.Control control) {
        return query(original, control, false);
    }
    @Override public CompletionStage<ObjectNode> cancel(Invocation original, NativeCalibrationApproval.Control control) {
        // The synchronous native queue has no background runner to kill or replay.
        return query(original, control, true);
    }
    private CompletionStage<ObjectNode> query(Invocation original, NativeCalibrationApproval.Control control, boolean cancel) {
        return CompletableFuture.completedFuture(NativeCalibrationFunctions.checked(() -> {
            current(original, control); String digest = started.get(original.invocationId());
            if (digest == null || !digest.equals(ContractJson.digest(original.wire()))) throw failure("INVOCATION_UNKNOWN");
            return ContractJson.newObject().put("invocationId", original.invocationId()).put("status", runs.containsKey(original.invocationId()) ? "complete" : "failed")
                    .put("effects", "unknown").put("cancellationRequested", cancel || control.cancellationRequested());
        }, control));
    }
    @Override public NativeCalibrationRunFacts lookup(Invocation original, NativeCalibrationApproval.Control control) {
        return NativeCalibrationFunctions.checked(() -> {
            current(original, control); var facts = runs.get(original.invocationId());
            if (facts == null) throw failure(NativeCalibrationSource.ISSUER_UNAVAILABLE);
            facts.checkCurrent(original, control); return facts;
        }, control);
    }
    private ServerLevel actualLevel(Invocation original) {
        ServerLevel actual = level.apply(original.context().path("dimension").asText());
        if (actual == null || actual.getServer() != server || server.getLevel(actual.dimension()) != actual) throw failure("CALIBRATION_RUN_SOURCE_STALE");
        return actual;
    }
    private long tick() { return Integer.toUnsignedLong(server.getTickCount()); }
    @Override public synchronized void close() { closed = true; prepared = null; runs.clear(); started.clear(); retained = 0; }

    private final class Trace implements NativeCalibrationStageHooks.Listener {
        private final Invocation original;
        private final NativeCalibrationApproval.Program program;
        private final NativeCalibrationFunctions.SelectedFunction function;
        private final ServerLevel actualLevel;
        private final Object topHandler;
        private final List<List<NativeCalibrationRunFacts.Event>> events = new ArrayList<>();
        private final List<Integer> returned = new ArrayList<>();
        private final List<Boolean> handlerOutcomes = new ArrayList<>();
        private final List<Throwable> nativeFailures = new ArrayList<>();
        private final long from;
        private NativeCalibrationApproval.Control control;
        private NativeCalibrationTargetImages.ImagePair preseed;
        private Object executionContext, functionFrame;
        private int ordinal = -1, sequence, pendingRef = -1;
        private boolean queueComplete, handlerPending;
        private Throwable boundaryFailure;
        private Trace(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationFunctions.SelectedFunction function,
                      ServerLevel actualLevel, Object topHandler) {
            this.original = original; this.program = program; this.function = function; this.actualLevel = actualLevel; this.topHandler = topHandler;
            from = tick();
            for (int i = 0; i < function.statements().size(); i++) { events.add(new ArrayList<>()); returned.add(null); handlerOutcomes.add(false); }
        }
        private void checkpoint() {
            if (control == null) throw failure("CALIBRATION_STAGE_SCOPE_CHANGED");
            current(original, control); function.checkCurrent(control); current(original, control);
        }
        @Override public void beforeEntry(Object entry, Object source, Object context, Object frame) {
            checkpoint();
            if (handlerPending || queueComplete || ordinal + 1 >= function.statements().size()
                    || function.statements().get(ordinal + 1).actualEntry() != entry) throw failure("CALIBRATION_ENTRY_ORDER_CHANGED");
            if (!(source instanceof CommandSourceStack stack) || stack.getServer() != server || stack.getLevel() != actualLevel)
                throw failure("CALIBRATION_RUN_SOURCE_STALE");
            if (executionContext == null) { executionContext = context; functionFrame = frame; }
            else if (executionContext != context || functionFrame != frame) throw failure("CALIBRATION_ENTRY_OWNER_CHANGED");
            ordinal++;
            if (ordinal == program.preseedEndIndex()) {
                preseed = NativeCalibrationTargetImages.observe(server, actualLevel, owner, original.context(), program, control);
                if (!preseed.objectiveFullTargetKnown() || !preseed.storageFullTargetKnown()) throw failure("CALIBRATION_PRESEED_INCOMPLETE");
                event(NativeCalibrationRunFacts.EventKind.PRESEED_CAPTURE, null, null, null, null, null, null, null, null);
            }
            event(NativeCalibrationRunFacts.EventKind.ENTRY_BEGIN, null, null, null, null, null, null, null, null); checkpoint();
        }
        private int selected(Object receiver, NativeCalibrationExecutables.Role role) {
            if (ordinal < 0) throw failure("CALIBRATION_ENTRY_MISSING");
            var refs = function.statements().get(ordinal).executableRefs();
            for (int local = 0; local < refs.size(); local++) {
                var fact = function.executables().facts().get(refs.get(local));
                if (fact.actualReceiver() == receiver && fact.role() == role) return local;
            }
            throw failure("CALIBRATION_SELECTED_EXECUTABLE_CHANGED");
        }
        @Override public void beforeHandler(Object handler, CommandContext<?> context) {
            checkpoint();
            if (handlerPending || ordinal < 0 || handlerOutcomes.get(ordinal) || !function.statements().get(ordinal).matchesTerminal(context)
                    || context.getCommand() != handler || !(context.getSource() instanceof CommandSourceStack stack)
                    || stack.getServer() != server || stack.getLevel() != actualLevel) throw failure("CALIBRATION_HANDLER_CHANGED");
            pendingRef = selected(handler, NativeCalibrationExecutables.Role.HANDLER); handlerPending = true; checkpoint();
        }
        @Override public void afterHandler(Object handler, CommandContext<?> context, Integer result, Throwable primary) {
            if (primary != null) {
                if (nativeFailures.size() >= MAX_EVENTS) throw failure("CALIBRATION_STAGE_LIMIT");
                nativeFailures.add(primary);
            }
            try { afterHandlerObserved(handler, context, result, primary); }
            catch (RuntimeException | Error post) { if (primary != null && boundaryFailure == null) boundaryFailure = primary; throw post; }
        }
        private void afterHandlerObserved(Object handler, CommandContext<?> context, Integer result, Throwable primary) {
            if (!handlerPending || pendingRef != selected(handler, NativeCalibrationExecutables.Role.HANDLER)
                    || !function.statements().get(ordinal).matchesTerminal(context)) throw failure("CALIBRATION_HANDLER_CHANGED");
            handlerPending = false;
            handlerOutcomes.set(ordinal, true);
            if (primary == null) {
                if (result == null || returned.get(ordinal) != null) throw failure("CALIBRATION_RETURN_MULTIPLE");
                returned.set(ordinal, result);
                event(NativeCalibrationRunFacts.EventKind.HANDLER_RETURN, pendingRef, result, null, null, null, null, null, null);
            } else {
                event(NativeCalibrationRunFacts.EventKind.HANDLER_FAILURE, pendingRef, null,
                        primary instanceof CommandSyntaxException ? "command_syntax" : primary instanceof Error ? "error" : "runtime", null, null, null, null, null);
            }
            pendingRef = -1; checkpoint();
        }
        @Override public void beforeCustom(Object receiver, Object chain, Object frame, boolean modifier) {
            checkpoint();
            // The original top-level function command queues CallFunction before any body entry.
            if (!(chain instanceof ContextChain<?> actual)) throw failure("CALIBRATION_CUSTOM_CHANGED");
            if (ordinal < 0) {
                if (receiver != topHandler || modifier || actual.getTopContext().getCommand() != receiver
                        || !program.command().equals(actual.getTopContext().getInput())) throw failure("CALIBRATION_TOP_COMMAND_CHANGED");
                return;
            }
            if (frame != functionFrame || !function.statements().get(ordinal).hasChain(chain)
                    || receiver != (modifier ? actual.getTopContext().getRedirectModifier() : actual.getTopContext().getCommand())) throw failure("CALIBRATION_CUSTOM_CHANGED");
            selected(receiver, modifier ? NativeCalibrationExecutables.Role.REDIRECT : NativeCalibrationExecutables.Role.HANDLER);
        }
        @Override public void afterCustom(Object receiver, Object chain, Object frame, boolean modifier, Throwable primary) {
            if (primary != null) {
                if (nativeFailures.size() >= MAX_EVENTS) throw failure("CALIBRATION_STAGE_LIMIT");
                nativeFailures.add(primary);
            }
            if (ordinal >= 0 && primary == null) event(NativeCalibrationRunFacts.EventKind.CUSTOM_RETURN,
                    selected(receiver, modifier ? NativeCalibrationExecutables.Role.REDIRECT : NativeCalibrationExecutables.Role.HANDLER), null, null,
                    modifier ? "modifier" : "command", null, null, null, null);
            try { checkpoint(); }
            catch (RuntimeException | Error post) { if (primary != null && boundaryFailure == null) boundaryFailure = primary; throw post; }
        }
        @Override public void frameReturned(Object frame, Integer result) {
            if (ordinal >= 0 && frame == functionFrame) event(NativeCalibrationRunFacts.EventKind.FRAME_RETURN, null, result, null, null, null, null, null, null);
            checkpoint();
        }
        @Override public void beforeFrameReturn(Object frame, Integer result) { checkpoint(); }
        @Override public void beforeResultCallback(CommandContext<?> context) {
            checkpoint();
            if (ordinal < 0 || !function.statements().get(ordinal).matchesTerminal(context)) throw failure("CALIBRATION_HANDLER_CHANGED");
        }
        @Override public void afterResultCallback(CommandContext<?> context, Throwable primary) {
            if (primary != null && nativeFailures.size() < MAX_EVENTS) nativeFailures.add(primary);
            try { beforeResultCallback(context); }
            catch (RuntimeException | Error post) { if (primary != null && boundaryFailure == null) boundaryFailure = primary; throw post; }
        }
        @Override public void queueReturned(Object context, int quota, boolean overflow, int queued, int newTop) {
            checkpoint();
            if (context != executionContext || queueComplete || handlerPending) throw failure("CALIBRATION_QUEUE_CHANGED");
            event(NativeCalibrationRunFacts.EventKind.QUEUE_RETURN, null, null, null, null, quota, overflow, queued, newTop);
            if (quota <= 0 || overflow || queued != 0 || newTop != 0 || ordinal + 1 != function.statements().size() || preseed == null)
                throw failure("CALIBRATION_QUEUE_INCOMPLETE");
            queueComplete = true; checkpoint();
        }
        private void event(NativeCalibrationRunFacts.EventKind kind, Integer ref, Integer value, String failureKind, String customKind,
                           Integer quota, Boolean overflow, Integer queued, Integer newTop) {
            if (ordinal < 0 || sequence >= MAX_EVENTS) throw failure("CALIBRATION_STAGE_LIMIT");
            events.get(ordinal).add(new NativeCalibrationRunFacts.Event(kind, sequence++, tick(), ref, value, failureKind, customKind, quota, overflow, queued, newTop));
        }
        private void requireComplete(NativeCalibrationApproval.Control originalControl) {
            current(original, originalControl);
            if (!queueComplete || handlerPending || ordinal + 1 != function.statements().size() || preseed == null) throw failure("CALIBRATION_QUEUE_INCOMPLETE");
        }
        private List<NativeCalibrationRunFacts.CommandFact> snapshot() {
            var result = new ArrayList<NativeCalibrationRunFacts.CommandFact>();
            for (int index = 0; index <= ordinal; index++) result.add(new NativeCalibrationRunFacts.CommandFact(function.statements().get(index), returned.get(index), events.get(index)));
            return List.copyOf(result);
        }
    }
    private static void preserve(Throwable primary, Throwable additional) {
        if (primary == additional || contains(primary, additional) || contains(additional, primary)) return;
        primary.addSuppressed(additional);
    }
    private static boolean contains(Throwable root, Throwable target) {
        var pending = new java.util.ArrayDeque<Throwable>(); var visited = new java.util.IdentityHashMap<Throwable, Boolean>(); pending.add(root);
        while (!pending.isEmpty()) {
            Throwable current = pending.removeFirst(); if (current == target) return true;
            if (visited.put(current, true) != null) continue;
            if (visited.size() >= MAX_EVENTS) return true;
            if (current.getCause() != null) pending.add(current.getCause());
            for (Throwable suppressed : current.getSuppressed()) { if (pending.size() >= MAX_EVENTS) return true; pending.add(suppressed); }
        }
        return false;
    }
    private static ContractException failure(String code) { return new ContractException(code, "Actual native calibration is unavailable, incomplete or changed"); }
}
