package io.github.daejunnom.mmmm.fabric;

import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Supplier;

/** Actual library-loader references only. Native owns selection, source meaning and receipts. */
public final class NativeFunctionLoadEntryContexts {
    private static final int MAX_SELECTED_PER_LIBRARY = 47;
    private static final int MAX_SELECTED_TOTAL = 8 * MAX_SELECTED_PER_LIBRARY;
    private static final int MAX_PREPARATION_DEPTH = 32;
    private static final Object REGISTRY = new Object();
    private static final IdentityHashMap<Object, IdentityHashMap<Object, SelectedEntry>> SELECTED = new IdentityHashMap<>();
    private static final ThreadLocal<Preparation> CURRENT = new ThreadLocal<>();
    private static int selectedCount;

    private NativeFunctionLoadEntryContexts() { }

    @SuppressWarnings("unchecked") // The pinned first thenCompose has this erased Function/CompletionStage shape.
    public static CompletableFuture<?> prepareThenCompose(Object actualLibrary,
            CompletableFuture<?> actualPriorFuture, Function<?, ?> originalFunction) {
        var prior = (CompletableFuture<Object>) actualPriorFuture;
        var original = (Function<Object, CompletionStage<Object>>) originalFunction;
        Function<Object, CompletionStage<Object>> callback = original;
        try {
            var observation = NativeFunctionLoadObservation.forLibrary(actualLibrary);
            if (observation != null) {
                callback = actualInput -> {
                    Preparation previous = previous();
                    Preparation frame = enter(observation, actualLibrary, actualPriorFuture,
                        originalFunction, actualInput, previous);
                    try {
                        if (frame != null) preparationEntered(frame);
                        CompletionStage<Object> actualStage;
                        try {
                            actualStage = original.apply(actualInput);
                        } catch (RuntimeException | Error actualFailure) {
                            if (frame != null) preparationFailed(frame, actualFailure);
                            throw actualFailure;
                        }
                        if (frame != null) preparationReturned(frame, actualStage);
                        return actualStage;
                    } finally {
                        leave(frame, previous);
                    }
                };
                // This observed receiver/continuation is a narrow starting point only: it does not
                // attest the preceding future producer, whole reload causality or SourceAdmission.
                // Native stores a distinct library-preparation role, never the outer core ticket.
                observation.preparationBound(actualLibrary, actualPriorFuture, originalFunction);
            }
        } catch (RuntimeException | Error unavailable) {
            // A preparation failure permits only the first original engine call below.
        }
        return prior.thenCompose(callback);
    }

    private static void preparationEntered(Preparation frame) {
        try {
            frame.observation.preparationEntered(frame.library, frame.priorFuture, frame.originalFunction,
                frame.inputMap, frame);
        } catch (RuntimeException | Error unavailable) { frame.valid = false; }
    }

    private static void preparationReturned(Preparation frame, Object actualReturnedStage) {
        try {
            frame.observation.preparationReturned(frame.library, frame.priorFuture, frame.originalFunction,
                frame.inputMap, frame, actualReturnedStage);
        } catch (RuntimeException | Error unavailable) { frame.valid = false; }
    }

    private static void preparationFailed(Preparation frame, Throwable actualFailure) {
        try {
            frame.observation.preparationFailed(frame.library, frame.priorFuture, frame.originalFunction,
                frame.inputMap, frame, actualFailure);
        } catch (RuntimeException | Error unavailable) { frame.valid = false; }
    }

    public static <T> T entryReturned(Object actualLibrary, Object actualIterator, T actualEntry) {
        try {
            Preparation frame = current(actualLibrary);
            if (frame != null) {
                if (frame.stage != 0 || actualEntry == null || actualIterator == null
                        || (frame.iterator != null && frame.iterator != actualIterator)) {
                    frame.valid = false;
                } else {
                    frame.iterator = actualIterator; frame.entry = actualEntry; frame.stage = 1;
                }
            }
        } catch (RuntimeException | Error unavailable) { invalidateCurrent(); }
        return actualEntry;
    }

    public static <T> T resourceKeyReturned(Object actualLibrary, Object actualEntry, T actualResourceId) {
        try {
            Preparation frame = current(actualLibrary);
            if (frame != null) {
                if (frame.stage != 1 || frame.entry != actualEntry || actualResourceId == null) frame.valid = false;
                else { frame.resourceId = actualResourceId; frame.stage = 2; }
            }
        } catch (RuntimeException | Error unavailable) { invalidateCurrent(); }
        return actualResourceId;
    }

    public static <T> T functionIdReturned(Object actualLibrary, Object actualLister,
            Object actualResourceId, T actualFunctionId) {
        try {
            Preparation frame = current(actualLibrary);
            if (frame != null) {
                if (frame.stage != 2 || frame.resourceId != actualResourceId || actualFunctionId == null
                        || actualLister == null || (frame.lister != null && frame.lister != actualLister)) {
                    frame.valid = false;
                } else {
                    frame.lister = actualLister; frame.functionId = actualFunctionId; frame.stage = 3;
                }
            }
        } catch (RuntimeException | Error unavailable) { invalidateCurrent(); }
        return actualFunctionId;
    }

    public static CompletableFuture<?> supplyAsyncEntry(Object actualLibrary,
            Supplier<?> originalSupplier, Executor actualExecutor) {
        return supplySelected(actualLibrary, originalSupplier, actualExecutor);
    }

    private static <T> CompletableFuture<T> supplySelected(Object actualLibrary,
            Supplier<T> originalSupplier, Executor actualExecutor) {
        SelectedEntry selected = null;
        NativeFunctionLoadObservation.TrackedSupplier<T> tracked = null;
        Preparation frame = null;
        try {
            frame = current(actualLibrary);
            if (frame != null && frame.stage == 3) {
                var route = frame.observation.selectEntry(actualLibrary, frame.entry, frame.functionId,
                    frame.resourceId, originalSupplier, frame.priorFuture, frame.originalFunction,
                    frame.inputMap, frame);
                if (route == NativeFunctionLoadObservation.EntryRouting.SELECT) {
                    selected = reserve(frame, originalSupplier, actualExecutor);
                    if (selected != null) {
                        tracked = frame.observation.entrySupplier(actualLibrary, selected.functionId,
                            originalSupplier, actualExecutor);
                    }
                }
            }
        } catch (RuntimeException | Error unavailable) {
            if (frame != null) frame.valid = false;
        } finally {
            if (frame != null) frame.clearEntry();
        }
        // No observer catch surrounds the engine. An executor may run S and then throw.
        // A SELECT tuple without a returned future stays quarantined, with a finite reference bound.
        CompletableFuture<T> actualFuture = CompletableFuture.supplyAsync(tracked == null ? originalSupplier : tracked, actualExecutor);
        if (selected != null && tracked != null) {
            try {
                selected.future = actualFuture;
                tracked.future(actualFuture);
                SelectedEntry actualSelected = selected;
                actualFuture.whenComplete((actualFunction, actualFailure) -> {
                    try {
                        actualSelected.observation.entryCompleted(actualFuture, actualSelected.functionId,
                            actualFunction, actualFailure);
                    } finally {
                        release(actualSelected);
                    }
                });
            } catch (RuntimeException | Error unavailable) {
                // Keep the selected tuple if future binding/terminal registration is uncertain.
            }
        }
        return actualFuture;
    }

    public static <T> T resourceReturned(Object actualLibrary, Object actualEntry,
            Object actualFunctionId, T actualResource) {
        try {
            SelectedEntry selected = selected(actualLibrary, actualEntry, actualFunctionId);
            if (selected != null && selected.resourceClaimed.compareAndSet(false, true)) {
                selected.resource = actualResource;
                selected.read = selected.observation.resource(actualLibrary, selected.functionId,
                    selected.resourceId, actualResource, selected.entry, selected.originalSupplier);
            }
        } catch (RuntimeException | Error unavailable) {
            // Missing native/read events remain incomplete; the original getter result is unchanged.
        }
        return actualResource;
    }

    public static List<String> readLinesReturned(Object actualResource, List<String> actualLines) {
        try {
            var read = NativeFunctionLoadObservation.forResource(actualResource);
            if (read != null) read.linesReturned(actualLines);
        } catch (RuntimeException | Error unavailable) { }
        return actualLines;
    }

    public static void readLinesFailed(Object actualResource, Throwable actualFailure) {
        try {
            var read = NativeFunctionLoadObservation.forResource(actualResource);
            if (read != null) read.linesFailed(actualFailure);
        } catch (RuntimeException | Error unavailable) { }
    }

    public static <T> T fromLinesReturned(Object actualLibrary, Object actualEntry,
            Object actualFunctionId, Object actualLines, T actualFunction) {
        compiled(actualLibrary, actualEntry, actualFunctionId, actualLines, actualFunction, null);
        return actualFunction;
    }

    public static void fromLinesFailed(Object actualLibrary, Object actualEntry,
            Object actualFunctionId, Object actualLines, Throwable actualFailure) {
        compiled(actualLibrary, actualEntry, actualFunctionId, actualLines, null, actualFailure);
    }

    private static void compiled(Object actualLibrary, Object actualEntry, Object actualFunctionId,
            Object actualLines, Object actualFunction, Throwable actualFailure) {
        try {
            SelectedEntry selected = selected(actualLibrary, actualEntry, actualFunctionId);
            if (selected != null && selected.read != null) {
                selected.read.compiled(actualLines, actualFunction, actualFailure);
            }
        } catch (RuntimeException | Error unavailable) { }
    }

    public static void functionsStored(Object actualLibrary, Object actualPublishedMap) {
        try {
            var observation = NativeFunctionLoadObservation.forLibrary(actualLibrary);
            if (observation != null) observation.functionsPublished(actualLibrary, actualPublishedMap);
        } catch (RuntimeException | Error unavailable) { }
    }

    private static Preparation previous() {
        try { return CURRENT.get(); }
        catch (RuntimeException | Error unavailable) { return null; }
    }

    private static Preparation enter(NativeFunctionLoadObservation observation, Object library,
            CompletableFuture<?> priorFuture, Function<?, ?> originalFunction, Object actualInput,
            Preparation previous) {
        try {
            if (!(actualInput instanceof Map<?, ?>) || (previous != null && previous.depth >= MAX_PREPARATION_DEPTH)) {
                CURRENT.remove(); return null;
            }
            var frame = new Preparation(observation, library, priorFuture, originalFunction, actualInput, previous);
            CURRENT.set(frame); return frame;
        } catch (RuntimeException | Error unavailable) {
            try { CURRENT.remove(); } catch (RuntimeException | Error cleanupUnavailable) { }
            return null;
        }
    }

    private static void leave(Preparation frame, Preparation previous) {
        try {
            if (frame != null) { frame.valid = false; frame.clearEntry(); }
            if (previous == null) CURRENT.remove(); else CURRENT.set(previous);
        } catch (RuntimeException | Error unavailable) { }
    }

    private static Preparation current(Object actualLibrary) {
        Preparation frame = CURRENT.get();
        return frame != null && frame.valid && frame.library == actualLibrary
            && NativeFunctionLoadObservation.forLibrary(actualLibrary) == frame.observation ? frame : null;
    }

    private static void invalidateCurrent() {
        try {
            Preparation frame = CURRENT.get();
            if (frame != null) frame.valid = false;
        } catch (RuntimeException | Error unavailable) { }
    }

    private static SelectedEntry reserve(Preparation frame, Supplier<?> originalSupplier, Executor actualExecutor) {
        synchronized (REGISTRY) {
            var entries = SELECTED.get(frame.library);
            if (selectedCount >= MAX_SELECTED_TOTAL || (entries != null
                    && (entries.size() >= MAX_SELECTED_PER_LIBRARY || entries.containsKey(frame.entry)))) return null;
            if (entries == null) { entries = new IdentityHashMap<>(); SELECTED.put(frame.library, entries); }
            var selected = new SelectedEntry(frame, originalSupplier, actualExecutor);
            entries.put(frame.entry, selected); selectedCount++; return selected;
        }
    }

    private static SelectedEntry selected(Object library, Object entry, Object functionId) {
        synchronized (REGISTRY) {
            var entries = SELECTED.get(library);
            SelectedEntry selected = entries == null ? null : entries.get(entry);
            return selected != null && selected.functionId == functionId
                && NativeFunctionLoadObservation.forLibrary(library) == selected.observation ? selected : null;
        }
    }

    private static void release(SelectedEntry selected) {
        try {
            synchronized (REGISTRY) {
                var entries = SELECTED.get(selected.library);
                if (entries != null && entries.get(selected.entry) == selected) {
                    entries.remove(selected.entry); selectedCount--;
                    if (entries.isEmpty()) SELECTED.remove(selected.library);
                }
            }
        } catch (RuntimeException | Error unavailable) { }
    }

    private static final class Preparation {
        private final NativeFunctionLoadObservation observation;
        private final Object library, inputMap;
        private final CompletableFuture<?> priorFuture;
        private final Function<?, ?> originalFunction;
        private final int depth;
        private boolean valid = true;
        private Object iterator, lister, entry, resourceId, functionId;
        private int stage;
        private Preparation(NativeFunctionLoadObservation observation, Object library,
                CompletableFuture<?> priorFuture, Function<?, ?> originalFunction, Object inputMap, Preparation previous) {
            this.observation = observation; this.library = library; this.priorFuture = priorFuture;
            this.originalFunction = originalFunction; this.inputMap = inputMap;
            this.depth = previous == null ? 1 : previous.depth + 1;
        }
        private void clearEntry() { entry = null; resourceId = null; functionId = null; stage = 0; }
    }

    private static final class SelectedEntry {
        private final NativeFunctionLoadObservation observation;
        private final Object library, entry, functionId, resourceId;
        private final Supplier<?> originalSupplier;
        private final Executor actualExecutor;
        private final AtomicBoolean resourceClaimed = new AtomicBoolean();
        private volatile CompletableFuture<?> future;
        private volatile Object resource;
        private volatile NativeFunctionLoadObservation.Read read;
        private SelectedEntry(Preparation frame, Supplier<?> originalSupplier, Executor actualExecutor) {
            this.observation = frame.observation; this.library = frame.library; this.entry = frame.entry;
            this.functionId = frame.functionId; this.resourceId = frame.resourceId;
            this.originalSupplier = originalSupplier; this.actualExecutor = actualExecutor;
        }
    }
}
