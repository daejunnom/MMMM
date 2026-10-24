package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.observer.DefinitionPackLoadBridge;
import io.github.daejunnom.mmmm.fabric.mixin.FixedPathPackReadAccess;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.FileSystems;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import net.minecraft.server.packs.FixedPathPackResources;
import net.minecraft.server.packs.PackType;
import net.minecraft.server.packs.resources.Resource;

/** Actual object and I/O relay only. Rust owns source meaning, admission and receipt bytes. */
public final class NativeFunctionLoadObservation {
    private static final int MAX_BINDINGS = 512;
    private static final byte[] EMPTY = new byte[0];
    private static final Object REGISTRY = new Object();
    private static final IdentityHashMap<Object, NativeFunctionLoadObservation> SELECTIONS = new IdentityHashMap<>();
    private static final IdentityHashMap<Object, NativeFunctionLoadObservation> MANAGERS = new IdentityHashMap<>();
    private static final IdentityHashMap<Object, NativeFunctionLoadObservation> LIBRARIES = new IdentityHashMap<>();
    private static final IdentityHashMap<Object, Read> READS = new IdentityHashMap<>();

    /** Fixed JNI operation numbers; no phase by itself claims successful loading. */
    public enum Phase {
        ARM(0), SUPPLIER_BOUND(1), SUPPLIER_RETURNED(2), SUPPLIER_FAILED(3), FUTURE_BOUND(4),
        FUNCTION_BOUND(5), FUNCTION_ENTERED(6), FUNCTION_RETURNED(7), FUNCTION_FAILED(8),
        CONSUMER_BOUND(9), CONSUMER_ENTERED(10), CONSUMER_RETURNED(11), CONSUMER_FAILED(12),
        OPERATION_BOUND(13), OPERATION_ENTERED(14), OPERATION_RETURNED(15), OPERATION_FAILED(16),
        MANAGER_BOUND(17), LIBRARY_BOUND(18), RESOURCE_BOUND(19), STREAM_BOUND(20), STREAM_READ(21),
        STREAM_EOF(22), STREAM_READ_FAILED(23), STREAM_CLOSE_SUCCEEDED(24), STREAM_CLOSE_FAILED(25),
        STREAM_SKIP_SUCCEEDED(26), STREAM_SKIP_FAILED(27), STREAM_RESET_SUCCEEDED(28),
        STREAM_RESET_FAILED(29), STREAM_MARK(30), COMPILED_FUNCTION_RETURNED(31),
        COMPILED_FUNCTION_FAILED(32), ENTRY_COMPLETED(33), FUNCTIONS_PUBLISHED(34),
        LIBRARY_REPLACED(35), RELOAD_COMPLETED(36), RELOAD_FAILED(37), RETIRED(38),
        STREAM_OPAQUE_READ(39), OBSERVATION_INVALID(40), READ_LINES_RETURNED(41), READ_LINES_FAILED(42),
        OBSERVE_CURRENT(43), READER_BOUND(44), RELOAD_FUTURE_BOUND(45), ENTRY_SELECTION(46),
        PACK_RUN_READINESS(47), PACK_RUN_OBSERVATION(48);
        private final int code;
        Phase(int code) { this.code = code; }
        public int code() { return code; }
    }

    public enum Reason { NATIVE_UNAVAILABLE, ACTUAL_IO_FAILED, IDENTITY_JOIN_UNAVAILABLE, DUPLICATE_CALLBACK,
        CONCURRENT_IO, NONLINEAR_IO, UNSUPPORTED_IO, INVALID_READ_RESULT, RETIRED }
    public record Failure(Phase phase, Reason reason, Throwable actualThrowable) { }
    /** Native routing only; no value grants source admission or Java domain authority. */
    public enum EntryRouting { IGNORE, SELECT, UNAVAILABLE }
    @FunctionalInterface public interface Operation<T, E extends Throwable> { T call() throws E; }

    private final Object server, attempt, invocation, sealedFiles, heldRootAnchor;
    private final String loadInvocationDigest;
    private final Collection<String> selection;
    private final Object failureLock = new Object();
    private final Object receiptLock = new Object();
    private final IllegalStateException boundaryFailure = new IllegalStateException("Actual loader observation is incomplete");
    private volatile boolean nativeUnavailable, retired;
    private final AtomicBoolean retirementClaimed = new AtomicBoolean();
    private volatile byte[] receipt = EMPTY;
    private Phase firstPhase;
    private Reason firstReason;
    private Throwable firstThrowable;

    private NativeFunctionLoadObservation(Object server, Object attempt, Object invocation, Object sealedFiles,
                                          Object heldRootAnchor, Collection<String> selection) {
        this.server = Objects.requireNonNull(server); this.attempt = Objects.requireNonNull(attempt);
        this.invocation = Objects.requireNonNull(invocation); this.sealedFiles = Objects.requireNonNull(sealedFiles);
        this.heldRootAnchor = Objects.requireNonNull(heldRootAnchor); this.selection = Objects.requireNonNull(selection);
        // Cached from the actual immutable SDK object. A caller's digest pin is never an issuer.
        loadInvocationDigest = invocation instanceof Invocation actual ? ContractJson.digest(actual.wire()) : null;
    }

    public static NativeFunctionLoadObservation begin(Object server, Object attempt, Object invocation,
            Object sealedFiles, Object heldRootAnchor, Collection<String> actualSelection) {
        var observation = new NativeFunctionLoadObservation(server, attempt, invocation, sealedFiles, heldRootAnchor, actualSelection);
        observation.bind(SELECTIONS, actualSelection);
        observation.binding(Phase.ARM, actualSelection, null, null, null, null, null, null, null, null);
        return observation;
    }
    public static NativeFunctionLoadObservation forSelection(Object actualSelection) {
        synchronized (REGISTRY) { return SELECTIONS.get(actualSelection); }
    }
    public static NativeFunctionLoadObservation forManager(Object actualManager) {
        synchronized (REGISTRY) { return MANAGERS.get(actualManager); }
    }
    public static NativeFunctionLoadObservation forLibrary(Object actualLibrary) {
        synchronized (REGISTRY) { return LIBRARIES.get(actualLibrary); }
    }
    public static Read forResource(Object actualResource) {
        synchronized (REGISTRY) { return READS.get(actualResource); }
    }

    public Failure firstFailure() {
        synchronized (failureLock) {
            return firstThrowable == null ? null : new Failure(firstPhase, firstReason, firstThrowable);
        }
    }
    /** Opaque original native output, never a Java-generated success flag or decoder. */
    public byte[] opaqueReceipt() { return receipt.clone(); }

    /** A new read-only caller supplies current authority separately from historical arm identities. */
    public byte[] observeCurrent(Object actualFreshCurrentPort) {
        var call = new NativeCall(this, Phase.OBSERVE_CURRENT, this);
        call.freshCurrentPort = Objects.requireNonNull(actualFreshCurrentPort);
        call.prepareScalars();
        // Keep current-call failure separate from the original source observation.
        // Never return a prior receipt after an unavailable current observation.
        return DefinitionPackLoadBridge.observe(call, EMPTY, 0, 0, Phase.OBSERVE_CURRENT.code());
    }

    /** Load-only observation: no future run Invocation exists at this boundary. */
    byte[] packRunReadiness(Object actualFreshCurrentPort, Object actualEntryPlain, Object actualDependencyPlain) {
        var call = new NativeCall(this, Phase.PACK_RUN_READINESS, this);
        call.freshCurrentPort = Objects.requireNonNull(actualFreshCurrentPort);
        call.input = Objects.requireNonNull(actualEntryPlain); call.result = Objects.requireNonNull(actualDependencyPlain);
        call.prepareScalars();
        return observePack(call, EMPTY);
    }

    /** Actual objects only. Intermediate verified events do not mean a completed run. */
    byte[] packRunObservation(Object actualFreshCurrentPort, Object actualEntryPlain, Object actualDependencyPlain,
            Invocation actualRun, int eventKind, Object owner, Object callee, Object source, Object context,
            Object parentFrame, Object childFrame, List<?> entries, Object provider, Object entry,
            Object queueEntry, Object action, Throwable failure, byte[] rawFacts) {
        if (eventKind < 0 || eventKind > 14) throw packUnavailable(null, null);
        var call = new NativeCall(this, Phase.PACK_RUN_OBSERVATION, Objects.requireNonNull(owner));
        call.freshCurrentPort = Objects.requireNonNull(actualFreshCurrentPort);
        call.input = Objects.requireNonNull(actualEntryPlain); call.result = Objects.requireNonNull(actualDependencyPlain);
        call.operation = Objects.requireNonNull(actualRun);
        call.runInvocationDigest = ContractJson.digest(actualRun.wire());
        call.offset = eventKind; call.callee = callee; call.source = source; call.context = context;
        call.parentFrame = parentFrame; call.childFrame = childFrame; call.entries = entries;
        call.provider = provider; call.entry = entry; call.queueEntry = queueEntry; call.action = action;
        call.throwable = failure; call.prepareScalars();
        byte[] actualFacts = Objects.requireNonNull(rawFacts);
        return observePack(call, actualFacts);
    }

    private static byte[] observePack(NativeCall call, byte[] rawFacts) {
        try {
            return requirePackReceipt(DefinitionPackLoadBridge.observe(call, rawFacts, 0, rawFacts.length,
                    call.phase.code()), call.phase.code());
        } catch (DefinitionPackLoadBridge.PackObservationFailure actual) {
            throw packUnavailable(actual.actualReceipt(), actual);
        } catch (RuntimeException | Error actual) {
            if (actual instanceof ContractException expected && "CAPABILITY_UNAVAILABLE".equals(expected.code())) throw expected;
            throw packUnavailable(null, actual);
        }
    }

    /** Closed native status framing only. Rust alone interprets the opaque payload. */
    static byte[] requirePackReceipt(byte[] raw, int expectedPhase) {
        if ((expectedPhase != 47 && expectedPhase != 48) || raw == null || raw.length < 12 || raw.length > 65536)
            throw packUnavailable(raw, null);
        byte[] value = raw.clone();
        byte[] magic = { 'M', 'M', 'M', 'M', 'P', 'R', '0', '1' };
        for (int index = 0; index < magic.length; index++) if (value[index] != magic[index]) throw packUnavailable(value, null);
        int length = (Byte.toUnsignedInt(value[10]) << 8) | Byte.toUnsignedInt(value[11]);
        if (Byte.toUnsignedInt(value[8]) != expectedPhase || value[9] != 1 || length == 0 || length != value.length - 12)
            throw packUnavailable(value, null);
        return value;
    }

    /** Preserves original bytes even when the native domain result is unavailable. */
    static final class PackObservationFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient byte[] originalReceipt;
        private PackObservationFailure(byte[] original, Throwable actual) {
            super("The native PACK event did not verify", actual);
            originalReceipt = original == null || original.length > 65536 ? null : original.clone();
        }
        byte[] originalReceipt() { return originalReceipt == null ? null : originalReceipt.clone(); }
    }
    private static ContractException packUnavailable(byte[] raw, Throwable actual) {
        var failure = new ContractException("CAPABILITY_UNAVAILABLE", "The actual PACK source or execution observation is unavailable");
        failure.initCause(new PackObservationFailure(raw, actual)); return failure;
    }

    private void retain(Phase phase, Reason reason, Throwable failure) {
        synchronized (failureLock) {
            if (firstThrowable == null) {
                firstPhase = phase; firstReason = reason;
                firstThrowable = failure == null ? boundaryFailure : failure;
            }
        }
    }
    private void invalid(Reason reason) {
        retain(Phase.OBSERVATION_INVALID, reason, null);
        try {
            var call = new NativeCall(this, Phase.OBSERVATION_INVALID, this); call.reason = reason;
            emit(call);
        } catch (RuntimeException | Error failure) { unavailable(Phase.OBSERVATION_INVALID, failure); }
    }
    private void unavailable(Phase phase, Throwable failure) {
        nativeUnavailable = true;
        retain(phase, Reason.NATIVE_UNAVAILABLE, failure);
    }
    private boolean bind(IdentityHashMap<Object, NativeFunctionLoadObservation> map, Object key) {
        boolean accepted;
        synchronized (REGISTRY) {
            accepted = !retired && key != null && (map.get(key) == this || (!map.containsKey(key) && map.size() < MAX_BINDINGS));
            if (accepted) map.put(key, this);
        }
        if (!accepted) invalid(Reason.IDENTITY_JOIN_UNAVAILABLE);
        return accepted;
    }
    private void emit(NativeCall call) { emit(call, EMPTY, 0, 0); }
    private void emit(NativeCall call, byte[] bytes, int offset, int length) {
        if (nativeUnavailable && call.phase != Phase.RETIRED) return;
        if (retired && call.phase != Phase.RETIRED) { retain(call.phase, Reason.RETIRED, null); return; }
        try {
            call.prepareScalars();
            byte[] actual = DefinitionPackLoadBridge.observe(call, bytes, offset, length, call.phase.code());
            synchronized (receiptLock) { if (!retired || call.phase == Phase.RETIRED) receipt = actual; }
        }
        catch (RuntimeException | Error failure) {
            unavailable(call.phase, failure);
        }
    }

    private void binding(Phase phase, Object owner, Object manager, Object library, Object input,
                         Object result, Object future, Object function, Object functionId, Throwable failure) {
        try {
            var call = new NativeCall(this, phase, owner); call.manager = manager; call.library = library;
            call.input = input; call.result = result; call.future = future; call.function = function;
            call.functionId = functionId; call.throwable = failure; emit(call);
        } catch (RuntimeException | Error unavailable) { unavailable(phase, unavailable); }
    }
    private void consumerEvent(Phase phase, Object owner, Object consumer, Object input, Throwable failure) {
        try {
            var call = new NativeCall(this, phase, owner); call.consumer = consumer;
            call.input = input; call.throwable = failure; emit(call);
        } catch (RuntimeException | Error unavailable) { unavailable(phase, unavailable); }
    }
    private void operationEvent(Phase phase, Object owner, Object operation, Object result, Throwable failure) {
        try {
            var call = new NativeCall(this, phase, owner); call.operation = operation;
            call.result = result; call.throwable = failure; emit(call);
        } catch (RuntimeException | Error unavailable) { unavailable(phase, unavailable); }
    }

    public <T> TrackedSupplier<T> supplier(Object actualOwner, Supplier<T> original, Executor actualExecutor) {
        return new TrackedSupplier<>(this, actualOwner, null, original, actualExecutor);
    }
    public <T> TrackedSupplier<T> entrySupplier(Object actualLibrary, Object actualFunctionId,
                                               Supplier<T> original, Executor actualExecutor) {
        if (forLibrary(actualLibrary) != this) invalid(Reason.IDENTITY_JOIN_UNAVAILABLE);
        return new TrackedSupplier<>(this, actualLibrary, actualFunctionId, original, actualExecutor);
    }
    public <T, R> TrackedFunction<T, R> function(TrackedSupplier<T> source,
            CompletableFuture<T> actualPriorFuture, Function<T, R> original) {
        return new TrackedFunction<>(this, source, actualPriorFuture, original);
    }
    public <T> Consumer<T> consumer(Object actualOwner, Consumer<T> original) {
        Objects.requireNonNull(original);
        var once = new AtomicBoolean();
        consumerEvent(Phase.CONSUMER_BOUND, actualOwner, original, null, null);
        return input -> {
            if (!once.compareAndSet(false, true)) invalid(Reason.DUPLICATE_CALLBACK);
            consumerEvent(Phase.CONSUMER_ENTERED, actualOwner, original, input, null);
            try {
                original.accept(input);
                consumerEvent(Phase.CONSUMER_RETURNED, actualOwner, original, input, null);
            } catch (RuntimeException | Error failure) {
                consumerEvent(Phase.CONSUMER_FAILED, actualOwner, original, input, failure); throw failure;
            }
        };
    }
    public <T, E extends Throwable> Operation<T, E> operation(Object actualOwner, Object actualOperation,
                                                              Operation<T, E> original) {
        Objects.requireNonNull(original); Objects.requireNonNull(actualOperation);
        var once = new AtomicBoolean();
        operationEvent(Phase.OPERATION_BOUND, actualOwner, actualOperation, null, null);
        return () -> {
            if (!once.compareAndSet(false, true)) invalid(Reason.DUPLICATE_CALLBACK);
            operationEvent(Phase.OPERATION_ENTERED, actualOwner, actualOperation, null, null);
            try {
                T value = original.call();
                operationEvent(Phase.OPERATION_RETURNED, actualOwner, actualOperation, value, null); return value;
            } catch (Throwable failure) {
                operationEvent(Phase.OPERATION_FAILED, actualOwner, actualOperation, null, failure); throw failure;
            }
        };
    }

    public void manager(TrackedFunction<?, ?> continuation, Object actualOpenedList, Object actualManager) {
        if (continuation.observation != this || continuation.input != actualOpenedList || !continuation.entered.get()
                || !continuation.managerClaimed.compareAndSet(false, true)) {
            invalid(Reason.IDENTITY_JOIN_UNAVAILABLE); return;
        }
        if (!bind(MANAGERS, actualManager)) return;
        binding(Phase.MANAGER_BOUND, continuation, actualManager, null, actualOpenedList, null, continuation.priorFuture, continuation.original, null, null);
    }
    public void library(Object actualManager, Object actualResources, Object actualLibrary) {
        if (forManager(actualManager) != this) { invalid(Reason.IDENTITY_JOIN_UNAVAILABLE); return; }
        if (!bind(LIBRARIES, actualLibrary)) return;
        binding(Phase.LIBRARY_BOUND, actualManager, actualManager, actualLibrary,
                actualResources, actualLibrary, null, null, null, null);
    }
    /** Phase 5 starts actual receiver/function observation only.
     * It proves no whole upstream producer chain, source admission or authority. */
    public void preparationBound(Object actualLibrary, Object actualReceiverFuture, Object actualOriginalFunction) {
        preparationEvent(Phase.FUNCTION_BOUND, actualLibrary, actualReceiverFuture, actualOriginalFunction,
                null, null, null, null);
    }
    public void preparationEntered(Object actualLibrary, Object actualReceiverFuture, Object actualOriginalFunction,
                                   Object actualInputMap, Object actualInvocationFrame) {
        preparationEvent(Phase.FUNCTION_ENTERED, actualLibrary, actualReceiverFuture, actualOriginalFunction,
                actualInputMap, actualInvocationFrame, null, null);
    }
    public void preparationReturned(Object actualLibrary, Object actualReceiverFuture, Object actualOriginalFunction,
                                    Object actualInputMap, Object actualInvocationFrame, Object actualReturnedStage) {
        preparationEvent(Phase.FUNCTION_RETURNED, actualLibrary, actualReceiverFuture, actualOriginalFunction,
                actualInputMap, actualInvocationFrame, actualReturnedStage, null);
    }
    public void preparationFailed(Object actualLibrary, Object actualReceiverFuture, Object actualOriginalFunction,
                                  Object actualInputMap, Object actualInvocationFrame, Throwable actualThrowable) {
        preparationEvent(Phase.FUNCTION_FAILED, actualLibrary, actualReceiverFuture, actualOriginalFunction,
                actualInputMap, actualInvocationFrame, null, actualThrowable);
    }
    private void preparationEvent(Phase phase, Object actualLibrary, Object actualReceiverFuture,
                                  Object actualOriginalFunction, Object actualInputMap, Object actualInvocationFrame,
                                  Object actualReturnedStage, Throwable actualThrowable) {
        try {
            var call = new NativeCall(this, phase, actualLibrary); call.library = actualLibrary;
            call.future = actualReceiverFuture; call.function = actualOriginalFunction;
            call.input = actualInputMap; call.operation = actualInvocationFrame;
            call.result = actualReturnedStage; call.throwable = actualThrowable; emit(call);
        } catch (RuntimeException | Error failure) { unavailable(phase, failure); }
    }
    public EntryRouting selectEntry(Object actualLibrary, Object actualEntry, Object actualFunctionIdentifier,
                                    Object actualResourceIdentifier, Object actualOriginalSupplier,
                                    Object actualPrepareReceiverFuture, Object actualPrepareFunction,
                                    Object actualInputMap, Object actualInvocationFrame) {
        try {
            var call = new NativeCall(this, Phase.ENTRY_SELECTION, actualEntry);
            call.entry = actualEntry; call.library = actualLibrary; call.functionId = actualFunctionIdentifier;
            call.resourceId = actualResourceIdentifier; call.supplier = actualOriginalSupplier;
            call.future = actualPrepareReceiverFuture; call.function = actualPrepareFunction;
            call.input = actualInputMap; call.operation = actualInvocationFrame;
            call.prepareScalars();
            byte[] routing = DefinitionPackLoadBridge.observe(call, EMPTY, 0, 0, Phase.ENTRY_SELECTION.code());
            if (routing.length != 2 || routing[0] != 1) throw new IllegalStateException("Native entry routing is unavailable or malformed");
            return switch (routing[1]) {
                case 0 -> EntryRouting.IGNORE;
                case 1 -> EntryRouting.SELECT;
                case 2 -> EntryRouting.UNAVAILABLE;
                default -> throw new IllegalStateException("Native entry routing is unavailable or malformed");
            };
        } catch (RuntimeException | Error failure) {
            retain(Phase.ENTRY_SELECTION, Reason.NATIVE_UNAVAILABLE, failure);
            return EntryRouting.UNAVAILABLE;
        }
    }
    public Read resource(Object actualLibrary, Object actualFunctionId, Object actualResourceId, Object actualResource,
                         Object actualEntry, Object actualOriginalSupplier) {
        var read = new Read(this, actualLibrary, actualFunctionId, actualResourceId, actualResource,
                actualEntry, actualOriginalSupplier);
        if (actualEntry == null || actualOriginalSupplier == null || forLibrary(actualLibrary) != this) {
            invalid(Reason.IDENTITY_JOIN_UNAVAILABLE); return read;
        }
        boolean accepted;
        synchronized (REGISTRY) {
            accepted = !retired && !READS.containsKey(actualResource) && READS.size() < MAX_BINDINGS;
            if (accepted) { read.bound = true; READS.put(actualResource, read); }
        }
        if (!accepted) { invalid(Reason.IDENTITY_JOIN_UNAVAILABLE); return read; }
        read.outcome(Phase.RESOURCE_BOUND, null, null, 0, 0); return read;
    }
    public void entryCompleted(Object actualFuture, Object actualFunctionId, Object actualFunction, Throwable actualFailure) {
        binding(Phase.ENTRY_COMPLETED, actualFuture, null, null, null, actualFunction, actualFuture, null, actualFunctionId, actualFailure);
    }
    public void functionsPublished(Object actualLibrary, Object actualPublishedMap) {
        binding(Phase.FUNCTIONS_PUBLISHED, actualLibrary, null, actualLibrary, null, actualPublishedMap, null, null, null, null);
    }
    public void libraryReplaced(Object actualServer, Object actualNewHolder, Object actualFunctionManager,
            Object actualLibrary, Object actualOriginalConsumer) {
        try {
            var call = new NativeCall(this, Phase.LIBRARY_REPLACED, actualFunctionManager);
            call.input = actualNewHolder; call.result = actualServer; call.library = actualLibrary;
            call.consumer = actualOriginalConsumer; emit(call);
        } catch (RuntimeException | Error unavailable) { unavailable(Phase.LIBRARY_REPLACED, unavailable); }
    }
    public void reloadCompleted(Object actualFuture, Throwable actualFailure) {
        binding(actualFailure == null ? Phase.RELOAD_COMPLETED : Phase.RELOAD_FAILED,
                actualFuture, null, null, null, null, actualFuture, null, null, actualFailure);
    }
    /** Bind the actual reloadResources return before any terminal observer is attached. */
    public void reloadFutureBound(CompletableFuture<?> actualOriginalReturnedFuture) {
        binding(Phase.RELOAD_FUTURE_BOUND, actualOriginalReturnedFuture, null, null,
                null, null, actualOriginalReturnedFuture, null, null, null);
    }
    public void retire() {
        if (!retirementClaimed.compareAndSet(false, true)) return;
        synchronized (receiptLock) { retired = true; }
        binding(Phase.RETIRED, this, null, null, null, null, null, null, null, null);
        synchronized (REGISTRY) {
            SELECTIONS.values().removeIf(value -> value == this);
            MANAGERS.values().removeIf(value -> value == this);
            LIBRARIES.values().removeIf(value -> value == this);
            READS.values().removeIf(value -> value.observation == this);
        }
    }

    public static final class TrackedSupplier<T> implements Supplier<T> {
        private final NativeFunctionLoadObservation observation;
        private final Object owner;
        private final Object functionId;
        private final Supplier<T> original;
        private final Executor executor;
        private final AtomicBoolean invoked = new AtomicBoolean();
        private final AtomicBoolean futureBound = new AtomicBoolean();
        private volatile CompletableFuture<T> future;
        private volatile Object result;
        private TrackedSupplier(NativeFunctionLoadObservation observation, Object owner, Object functionId, Supplier<T> original, Executor executor) {
            this.observation = observation; this.owner = owner; this.functionId = functionId;
            this.original = Objects.requireNonNull(original); this.executor = executor;
            report(Phase.SUPPLIER_BOUND, null, null);
        }
        private NativeCall event(Phase phase) {
            var call = new NativeCall(observation, phase, owner); call.supplier = original;
            call.executor = executor; call.future = future; call.functionId = functionId; call.input = this; return call;
        }
        private void report(Phase phase, Object value, Throwable failure) {
            try {
                var call = event(phase); call.result = value; call.throwable = failure; observation.emit(call);
            } catch (RuntimeException | Error unavailable) { observation.unavailable(phase, unavailable); }
        }
        public void future(CompletableFuture<T> actualFuture) {
            if (!futureBound.compareAndSet(false, true)) { observation.invalid(Reason.DUPLICATE_CALLBACK); return; }
            future = actualFuture; report(Phase.FUTURE_BOUND, null, null);
        }
        @Override public T get() {
            if (!invoked.compareAndSet(false, true)) observation.invalid(Reason.DUPLICATE_CALLBACK);
            try {
                T value = original.get(); result = value;
                report(Phase.SUPPLIER_RETURNED, value, null); return value;
            } catch (RuntimeException | Error failure) {
                report(Phase.SUPPLIER_FAILED, null, failure); throw failure;
            }
        }
    }
    public static final class TrackedFunction<T, R> implements Function<T, R> {
        private final NativeFunctionLoadObservation observation;
        private final TrackedSupplier<T> source;
        private final CompletableFuture<T> priorFuture;
        private final Function<T, R> original;
        private final AtomicBoolean entered = new AtomicBoolean();
        private final AtomicBoolean managerClaimed = new AtomicBoolean();
        private volatile Object input;
        private TrackedFunction(NativeFunctionLoadObservation observation, TrackedSupplier<T> source,
                                CompletableFuture<T> priorFuture, Function<T, R> original) {
            this.observation = observation; this.source = Objects.requireNonNull(source);
            this.priorFuture = priorFuture; this.original = Objects.requireNonNull(original);
            if (source.observation != observation || source.future != priorFuture) observation.invalid(Reason.IDENTITY_JOIN_UNAVAILABLE);
            report(Phase.FUNCTION_BOUND, null, null);
        }
        private NativeCall event(Phase phase) {
            var call = new NativeCall(observation, phase, source.owner); call.supplier = source.original;
            call.future = priorFuture; call.function = original; call.input = input; return call;
        }
        private void report(Phase phase, Object value, Throwable failure) {
            try {
                var call = event(phase); call.result = value; call.throwable = failure; observation.emit(call);
            } catch (RuntimeException | Error unavailable) { observation.unavailable(phase, unavailable); }
        }
        @Override public R apply(T actualInput) {
            if (!entered.compareAndSet(false, true)) observation.invalid(Reason.DUPLICATE_CALLBACK);
            input = actualInput;
            if (source.result != actualInput || source.future != priorFuture) observation.invalid(Reason.IDENTITY_JOIN_UNAVAILABLE);
            report(Phase.FUNCTION_ENTERED, null, null);
            try {
                R value = original.apply(actualInput);
                report(Phase.FUNCTION_RETURNED, value, null); return value;
            } catch (RuntimeException | Error failure) {
                report(Phase.FUNCTION_FAILED, null, failure); throw failure;
            }
        }
    }

    public static final class Read {
        private final NativeFunctionLoadObservation observation;
        private final Object library, functionId, resourceId, resource, entry, supplier;
        private final AtomicBoolean opened = new AtomicBoolean();
        private final AtomicBoolean readerBound = new AtomicBoolean();
        private volatile boolean bound;
        private volatile Object stream, reader;
        private Read(NativeFunctionLoadObservation observation, Object library, Object functionId, Object resourceId,
                     Object resource, Object entry, Object supplier) {
            this.observation = observation; this.library = library; this.functionId = functionId;
            this.resourceId = resourceId; this.resource = Objects.requireNonNull(resource);
            this.entry = entry; this.supplier = supplier;
        }
        private NativeCall event(Phase phase) {
            var call = new NativeCall(observation, phase, this); call.library = library; call.functionId = functionId;
            call.resourceId = resourceId; call.resource = resource; call.stream = stream; call.reader = reader;
            call.entry = entry; call.supplier = supplier;
            call.captureSource(); return call;
        }
        private void outcome(Phase phase, Object result, Throwable failure, long amount, long requested) {
            outcome(phase, null, result, failure, amount, requested);
        }
        private void outcome(Phase phase, Object input, Object result, Throwable failure, long amount, long requested) {
            if (!bound) return;
            try {
                var call = event(phase); call.input = input; call.result = result; call.throwable = failure;
                call.amount = amount; call.requested = requested; observation.emit(call);
            } catch (RuntimeException | Error unavailable) { observation.unavailable(phase, unavailable); }
        }
        private void data(byte[] bytes, int offset, int requested, int actual) {
            try {
                if (requested < 0 || (requested == 0 && actual != 0) || (requested > 0 && actual == 0)
                        || actual < -1 || actual > requested) {
                    observation.invalid(Reason.INVALID_READ_RESULT); return;
                }
                if (actual == 0) return;
                var call = event(actual == -1 ? Phase.STREAM_EOF : Phase.STREAM_READ);
                call.amount = actual; call.requested = requested; call.offset = offset;
                if (actual == -1) observation.emit(call);
                else observation.emit(call, bytes, offset, actual);
            } catch (RuntimeException | Error unavailable) { observation.unavailable(Phase.STREAM_READ, unavailable); }
        }
        private void singleByte(int actual) {
            try {
                if (actual == -1) outcome(Phase.STREAM_EOF, null, null, -1, 1);
                else if (actual < 0 || actual > 255) observation.invalid(Reason.INVALID_READ_RESULT);
                else {
                    byte[] bytes = {(byte) actual};
                    var call = event(Phase.STREAM_READ); call.amount = 1; call.requested = 1;
                    observation.emit(call, bytes, 0, 1);
                }
            } catch (RuntimeException | Error unavailable) { observation.unavailable(Phase.STREAM_READ, unavailable); }
        }
        public InputStream opened(Object actualResource, InputStream actualReturnedStream) {
            if (!bound) return actualReturnedStream;
            if (actualResource != resource || !opened.compareAndSet(false, true)) {
                observation.invalid(Reason.IDENTITY_JOIN_UNAVAILABLE); return actualReturnedStream;
            }
            stream = actualReturnedStream; outcome(Phase.STREAM_BOUND, null, null, 0, 0);
            if (actualReturnedStream == null) {
                observation.invalid(Reason.IDENTITY_JOIN_UNAVAILABLE); return null;
            }
            try { return new ObservedStream(this, actualReturnedStream); }
            catch (RuntimeException | Error failure) { observation.unavailable(Phase.STREAM_BOUND, failure); return actualReturnedStream; }
        }
        public void linesReturned(List<String> actualLines) {
            outcome(Phase.READ_LINES_RETURNED, actualLines, null, 0, 0);
        }
        public void readerOpened(Object actualReader) {
            if (!bound) return;
            if (!readerBound.compareAndSet(false, true)) { observation.invalid(Reason.DUPLICATE_CALLBACK); return; }
            reader = actualReader; outcome(Phase.READER_BOUND, null, actualReader, null, 0, 0);
        }
        public void linesFailed(Throwable actualFailure) {
            outcome(Phase.READ_LINES_FAILED, null, actualFailure, 0, 0);
        }
        public void compiled(Object actualLines, Object actualFunction, Throwable actualFailure) {
            outcome(actualFailure == null ? Phase.COMPILED_FUNCTION_RETURNED : Phase.COMPILED_FUNCTION_FAILED,
                    actualLines, actualFunction, actualFailure, 0, 0);
        }
    }

    /** No I/O lock: the original stream may need concurrent close to unblock a read. */
    private static final class ObservedStream extends InputStream {
        private final Read read;
        private final InputStream original;
        private final AtomicBoolean observing = new AtomicBoolean();
        private ObservedStream(Read read, InputStream original) { this.read = read; this.original = original; }
        private boolean enter() {
            boolean entered = observing.compareAndSet(false, true);
            if (!entered) read.observation.invalid(Reason.CONCURRENT_IO);
            return entered;
        }
        private void leave(boolean entered) { if (entered) observing.set(false); }
        private void failure(Phase phase, Throwable failure) {
            read.observation.retain(phase, Reason.ACTUAL_IO_FAILED, failure);
            read.outcome(phase, null, failure, 0, 0);
        }
        @Override public int read() throws IOException {
            boolean entered = enter();
            try {
                int value = original.read();
                read.singleByte(value);
                return value;
            } catch (IOException | RuntimeException | Error failure) { failure(Phase.STREAM_READ_FAILED, failure); throw failure; }
            finally { leave(entered); }
        }
        @Override public int read(byte[] bytes) throws IOException {
            boolean entered = enter();
            try { int value = original.read(bytes); read.data(bytes, 0, bytes.length, value); return value; }
            catch (IOException | RuntimeException | Error failure) { failure(Phase.STREAM_READ_FAILED, failure); throw failure; }
            finally { leave(entered); }
        }
        @Override public int read(byte[] bytes, int offset, int length) throws IOException {
            boolean entered = enter();
            try { int value = original.read(bytes, offset, length); read.data(bytes, offset, length, value); return value; }
            catch (IOException | RuntimeException | Error failure) { failure(Phase.STREAM_READ_FAILED, failure); throw failure; }
            finally { leave(entered); }
        }
        @Override public long skip(long requested) throws IOException {
            boolean entered = enter();
            try {
                long skipped = original.skip(requested);
                if (skipped > 0) read.observation.invalid(Reason.NONLINEAR_IO);
                read.outcome(Phase.STREAM_SKIP_SUCCEEDED, null, null, skipped, requested); return skipped;
            } catch (IOException | RuntimeException | Error failure) { failure(Phase.STREAM_SKIP_FAILED, failure); throw failure; }
            finally { leave(entered); }
        }
        @Override public int available() throws IOException { return original.available(); }
        @Override public boolean markSupported() { return original.markSupported(); }
        @Override public void mark(int limit) {
            boolean entered = enter();
            try { original.mark(limit); read.outcome(Phase.STREAM_MARK, null, null, limit, limit); }
            catch (RuntimeException | Error failure) { failure(Phase.STREAM_MARK, failure); throw failure; }
            finally { leave(entered); }
        }
        @Override public void reset() throws IOException {
            boolean entered = enter();
            try {
                original.reset(); read.observation.invalid(Reason.NONLINEAR_IO);
                read.outcome(Phase.STREAM_RESET_SUCCEEDED, null, null, 0, 0);
            } catch (IOException | RuntimeException | Error failure) { failure(Phase.STREAM_RESET_FAILED, failure); throw failure; }
            finally { leave(entered); }
        }
        @Override public void close() throws IOException {
            boolean entered = enter();
            try { original.close(); read.outcome(Phase.STREAM_CLOSE_SUCCEEDED, null, null, 0, 0); }
            catch (IOException | RuntimeException | Error failure) { failure(Phase.STREAM_CLOSE_FAILED, failure); throw failure; }
            finally { leave(entered); }
        }
        // Preserve delegate helper semantics. These opaque bypasses cannot prove linear raw coverage.
        private void opaque() { read.observation.invalid(Reason.UNSUPPORTED_IO); read.outcome(Phase.STREAM_OPAQUE_READ, null, null, 0, 0); }
        @Override public byte[] readAllBytes() throws IOException { opaque(); return original.readAllBytes(); }
        @Override public byte[] readNBytes(int length) throws IOException { opaque(); return original.readNBytes(length); }
        @Override public int readNBytes(byte[] bytes, int offset, int length) throws IOException { opaque(); return original.readNBytes(bytes, offset, length); }
        @Override public void skipNBytes(long length) throws IOException { opaque(); original.skipNBytes(length); }
        @Override public long transferTo(OutputStream target) throws IOException { opaque(); return original.transferTo(target); }
    }

    /** Exact private actual-object port. JNI checks this class/generation and re-reads its bindings. */
    private static final class NativeCall {
        private final NativeFunctionLoadObservation observation;
        private final Phase phase;
        private final Object owner;
        private Object supplier, executor, future, function, consumer, operation, input, result;
        private Object manager, library, functionId, resourceId, resource, stream, reader, entry;
        private Object freshCurrentPort;
        private Object callee, source, context, parentFrame, childFrame, entries, provider, queueEntry, action;
        private String runInvocationDigest;
        private Object sourcePack;
        private String selectedRoot;
        private byte[] scalars;
        private Throwable throwable;
        private Reason reason;
        private int offset;
        private long amount, requested;
        private NativeCall(NativeFunctionLoadObservation observation, Phase phase, Object owner) {
            this.observation = observation; this.phase = phase; this.owner = owner;
        }
        /** Capture once before JNI. Getters below never call back into the observer. */
        private void captureSource() {
            try {
                if (!(resource instanceof Resource actualResource) || actualResource.getClass() != Resource.class) return;
                Object actualSource = actualResource.source();
                sourcePack = actualSource;
                if (actualSource == null || actualSource.getClass() != FixedPathPackResources.class
                        || !(actualSource instanceof FixedPathPackReadAccess access)) return;
                var roots = access.mmmm$rootPaths();
                if (roots == null || roots.size() != 1) return;
                var root = roots.getFirst();
                if (root == null || root.getFileSystem() != FileSystems.getDefault()) return;
                // Deliberately supported shape only; this is no native directory-identity proof.
                var pathsForType = access.mmmm$pathsForType();
                if (pathsForType == null) return;
                var dataPaths = pathsForType.get(PackType.SERVER_DATA);
                if (dataPaths == null || dataPaths.size() != 1) return;
                var dataPath = dataPaths.getFirst();
                if (dataPath == null || dataPath.getFileSystem() != FileSystems.getDefault()
                        || !dataPath.equals(root.resolve("data"))) return;
                selectedRoot = root.toString();
            } catch (RuntimeException | Error failure) {
                // Keep the actual source object when later metadata is unavailable.
                selectedRoot = null;
                observation.retain(phase, Reason.IDENTITY_JOIN_UNAVAILABLE, failure);
            }
        }
        private void prepareScalars() {
            scalars = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN)
                    .putInt(phase.code()).putLong(amount).putLong(requested).putInt(offset).array();
        }
        private Object nativeServer() { return observation.server; }
        private Object nativeAttempt() { return observation.attempt; }
        private Object nativeInvocation() { return observation.invocation; }
        private String nativeLoadInvocationDigest() { return observation.loadInvocationDigest; }
        private String nativeRunInvocationDigest() { return runInvocationDigest; }
        private Object nativeSealedFiles() { return observation.sealedFiles; }
        private Object nativeHeldRootAnchor() { return observation.heldRootAnchor; }
        private Object nativeSelection() { return observation.selection; }
        private Object nativeOwner() { return owner; }
        private Object nativeSupplier() { return supplier; }
        private Object nativeExecutor() { return executor; }
        private Object nativeFuture() { return future; }
        private Object nativeFunction() { return function; }
        private Object nativeConsumer() { return consumer; }
        private Object nativeOperation() { return operation; }
        private Object nativeInput() { return input; }
        private Object nativeResult() { return result; }
        private Object nativeManager() { return manager; }
        private Object nativeLibrary() { return library; }
        private Object nativeEntry() { return entry; }
        private Object nativeFunctionId() { return functionId; }
        private Object nativeResourceId() { return resourceId; }
        private Object nativeResource() { return resource; }
        private Object nativeStream() { return stream; }
        private Object nativeReader() { return reader; }
        private Object nativeSourcePack() { return sourcePack; }
        private String nativeSelectedRoot() { return selectedRoot; }
        /** Fixed factual scalar layout; domain parsing and receipt ownership remain native. */
        private byte[] nativeScalars() { return scalars; }
        private Object nativeFreshCurrentPort() { return freshCurrentPort; }
        private Object nativeCallee() { return callee; }
        private Object nativeSource() { return source; }
        private Object nativeContext() { return context; }
        private Object nativeParentFrame() { return parentFrame; }
        private Object nativeChildFrame() { return childFrame; }
        private Object nativeEntries() { return entries; }
        private Object nativeProvider() { return provider; }
        private Object nativeQueueEntry() { return queueEntry; }
        private Object nativeAction() { return action; }
        private Throwable nativeObservationFailure() {
            synchronized (observation.failureLock) { return observation.firstThrowable; }
        }
        private String nativeObservationFailureReason() {
            synchronized (observation.failureLock) {
                return observation.firstReason == null ? null : observation.firstReason.name();
            }
        }
        private Throwable nativeThrowable() { return throwable; }
        private String nativeReason() { return reason == null ? null : reason.name(); }
        private int nativePhase() { return phase.code(); }
        private long nativeAmount() { return amount; }
        private long nativeRequested() { return requested; }
        private int nativeOffset() { return offset; }
    }
}
