package io.github.daejunnom.mmmm.fabric;

import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/** Factual carriers for the pinned outer reload callsites, never admission or receipt parsing. */
public final class NativeFunctionLoadHookContexts {
    // These are Java reference/stack bounds. Native owns capture capacity and retirement.
    private static final int MAX_BINDINGS = 512;
    private static final int MAX_CARRIER_DEPTH = 32;
    private static final Object REGISTRY = new Object();
    private static final IdentityHashMap<NativeFunctionLoadObservation, Capture> CAPTURES = new IdentityHashMap<>();
    private static final ThreadLocal<Frame> CURRENT = new ThreadLocal<>();
    private static final ThreadLocal<ConsumerFrame> CURRENT_CONSUMER = new ThreadLocal<>();

    private NativeFunctionLoadHookContexts() { }

    public static <T> CompletableFuture<T> supplyAsync(Object actualServer, Collection<String> actualSelection,
            Supplier<T> original, Executor actualExecutor) {
        Capture capture = null;
        NativeFunctionLoadObservation.TrackedSupplier<T> tracked = null;
        try {
            var observation = NativeFunctionLoadObservation.forSelection(actualSelection);
            capture = reserve(observation, actualServer, actualSelection);
            if (capture != null) {
                tracked = capture.observation.supplier(actualServer, original, actualExecutor);
                capture.source = tracked;
            }
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
        }
        // The engine call stays outside observer catches: an executor can act and then throw.
        CompletableFuture<T> actualFuture = null;
        try {
            actualFuture = CompletableFuture.supplyAsync(tracked == null ? original : tracked, actualExecutor);
        } finally {
            // No terminal future exists when scheduling throws, even if the executor already acted.
            // Drop only Java carriers; native keeps its partial/unknown observation.
            if (actualFuture == null) cleanup(capture);
        }
        if (tracked != null) {
            try {
                capture.sourceFuture = actualFuture;
                tracked.future(actualFuture);
            } catch (RuntimeException | Error unavailable) {
                disable(capture);
            }
        }
        return actualFuture;
    }

    @SuppressWarnings("unchecked") // Exact erased thenCompose descriptor; no callback is reconstructed.
    public static CompletableFuture<?> thenCompose(Object actualServer, Collection<String> actualSelection,
            CompletableFuture<?> actualPriorFuture, Function<?, ?> original) {
        var prior = (CompletableFuture<Object>) actualPriorFuture;
        var originalFunction = (Function<Object, CompletionStage<Object>>) original;
        Function<Object, CompletionStage<Object>> actualCallback = originalFunction;
        Capture capture = null;
        try {
            capture = current(actualServer, actualSelection);
            if (capture != null && capture.claimCompose(actualPriorFuture)) {
                var source = (NativeFunctionLoadObservation.TrackedSupplier<Object>) capture.source;
                var tracked = capture.observation.function(source, prior, originalFunction);
                capture.continuation = tracked;
                capture.originalFunction = original;
                Capture actualCapture = capture;
                actualCallback = input -> {
                    Frame previous = previous(actualCapture);
                    Frame frame = enter(actualCapture, tracked, actualPriorFuture, original, input, previous);
                    try {
                        // TrackedFunction invokes the actual original Function once and preserves its exception.
                        return tracked.apply(input);
                    } finally {
                        leave(frame, previous, actualCapture);
                    }
                };
            }
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
        }
        CompletableFuture<Object> actualFuture = null;
        try {
            actualFuture = prior.thenCompose(actualCallback);
        } finally {
            if (actualFuture == null) cleanup(capture);
        }
        if (capture != null) {
            try { capture.composedFuture = actualFuture; }
            catch (RuntimeException | Error unavailable) { disable(capture); }
        }
        return actualFuture;
    }

    @SuppressWarnings("unchecked") // The pinned thenAcceptAsync receives the original erased Consumer.
    public static CompletableFuture<Void> thenAcceptAsync(Object actualServer, Collection<String> actualSelection,
            CompletableFuture<?> actualPriorFuture, Consumer<?> original, Executor actualExecutor) {
        var prior = (CompletableFuture<Object>) actualPriorFuture;
        var originalConsumer = (Consumer<Object>) original;
        Consumer<Object> actualCallback = originalConsumer;
        Capture capture = null;
        try {
            capture = current(actualServer, actualSelection);
            if (capture != null && capture.claimConsumer(actualPriorFuture)) {
                var tracked = capture.observation.consumer(actualServer, originalConsumer);
                capture.consumerPriorFuture = actualPriorFuture;
                capture.originalConsumer = original;
                Capture actualCapture = capture;
                actualCallback = input -> {
                    ConsumerFrame previous = previousConsumer(actualCapture);
                    ConsumerFrame frame = enterConsumer(actualCapture, actualServer, actualPriorFuture, original, input, previous);
                    try {
                        tracked.accept(input);
                    } finally {
                        leaveConsumer(frame, previous, actualCapture);
                    }
                };
            }
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
        }
        CompletableFuture<Void> actualFuture = null;
        try {
            actualFuture = prior.thenAcceptAsync(actualCallback, actualExecutor);
        } finally {
            if (actualFuture == null) cleanup(capture);
        }
        if (capture != null) {
            try { capture.terminalFuture = actualFuture; }
            catch (RuntimeException | Error unavailable) { disable(capture); }
        }
        return actualFuture;
    }

    public static void managerCreated(Object actualServer, Object actualOpenedList, Object actualManager) {
        Capture capture = null;
        try {
            Frame frame = CURRENT.get();
            if (frame == null) return;
            capture = frame.capture;
            if (!capture.usable || capture.server != actualServer || capture.selection != frame.selection
                    || frame.input != actualOpenedList || capture.sourceFuture != frame.priorFuture
                    || capture.originalFunction != frame.originalFunction || capture.continuation != frame.continuation
                    || !frame.managerClaimed.compareAndSet(false, true)) {
                disable(capture); return;
            }
            // The wrapper is only an opaque carrier. Native must join the retained original future,
            // original Function and actual input from phases 5/6; wrapper identity is no authority.
            capture.observation.manager(frame.continuation, actualOpenedList, actualManager);
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
        }
    }

    /** Called only after the actual FunctionManager setter, inside its actual outer consumer. */
    public static void libraryInstalled(Object actualFunctionManager, Object actualLibrary) {
        Capture capture = null;
        try {
            ConsumerFrame frame = CURRENT_CONSUMER.get();
            if (frame == null) return;
            capture = frame.capture;
            if (!capture.usable || frame.server != capture.server
                    || frame.priorFuture != capture.composedFuture || frame.priorFuture != capture.consumerPriorFuture
                    || frame.originalConsumer != capture.originalConsumer
                    || NativeFunctionLoadObservation.forLibrary(actualLibrary) != capture.observation
                    || !frame.libraryClaimed.compareAndSet(false, true)) {
                disable(capture); return;
            }
            // Native checks current server/holder/manager getters; this frame grants no authority.
            capture.observation.libraryReplaced(frame.server, frame.input, actualFunctionManager, actualLibrary, frame.originalConsumer);
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
        }
    }

    /** Observe the actual method return; never replace it with a monitoring stage. */
    public static void returned(Object actualServer, Collection<String> actualSelection,
            CompletableFuture<?> actualOriginalReturnedFuture) {
        Capture capture = null;
        try {
            capture = current(actualServer, actualSelection);
            if (capture == null) return;
            Capture actualCapture = capture;
            boolean completeCarrier = capture.usable && capture.terminalFuture == actualOriginalReturnedFuture;
            if (completeCarrier) capture.observation.reloadFutureBound(actualOriginalReturnedFuture);
            // A previously completed future can invoke this inline: the binding above must come first.
            actualOriginalReturnedFuture.whenComplete((unused, actualFailure) -> {
                try {
                    if (completeCarrier && actualCapture.usable) {
                        actualCapture.observation.reloadCompleted(actualOriginalReturnedFuture, actualFailure);
                    }
                } finally {
                    cleanup(actualCapture);
                }
            });
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
            cleanup(capture);
        }
    }

    /** The pinned outer pre-return call threw; release Java carriers, without issuing a terminal receipt. */
    public static void failedBeforeReturn(Object actualServer, Collection<String> actualSelection) {
        Capture capture = null;
        try { capture = current(actualServer, actualSelection); }
        catch (RuntimeException | Error unavailable) { disable(capture); }
        finally { cleanup(capture); }
    }

    private static Capture reserve(NativeFunctionLoadObservation observation, Object actualServer,
            Collection<String> actualSelection) {
        if (observation == null) return null;
        synchronized (REGISTRY) {
            Capture existing = CAPTURES.get(observation);
            if (existing != null) { existing.usable = false; return null; }
            if (CAPTURES.size() >= MAX_BINDINGS) return null;
            var capture = new Capture(observation, actualServer, actualSelection);
            CAPTURES.put(observation, capture);
            return capture;
        }
    }

    private static Capture current(Object actualServer, Collection<String> actualSelection) {
        var observation = NativeFunctionLoadObservation.forSelection(actualSelection);
        synchronized (REGISTRY) {
            Capture capture = CAPTURES.get(observation);
            return capture != null && capture.server == actualServer && capture.selection == actualSelection ? capture : null;
        }
    }

    private static Frame previous(Capture capture) {
        try { return CURRENT.get(); }
        catch (RuntimeException | Error unavailable) { disable(capture); return null; }
    }

    private static Frame enter(Capture capture, NativeFunctionLoadObservation.TrackedFunction<?, ?> continuation,
            CompletableFuture<?> actualPriorFuture, Function<?, ?> originalFunction, Object actualInput, Frame previous) {
        try {
            if (!capture.usable || (previous != null && previous.depth >= MAX_CARRIER_DEPTH)) {
                disable(capture);
                // A declined nested carrier must not expose the preceding capture's frame.
                CURRENT.remove(); return null;
            }
            var frame = new Frame(capture, continuation, actualPriorFuture, originalFunction, actualInput, previous);
            CURRENT.set(frame);
            return frame;
        } catch (RuntimeException | Error unavailable) {
            try { CURRENT.remove(); }
            catch (RuntimeException | Error cleanupUnavailable) { disable(capture); }
            disable(capture); return null;
        }
    }

    private static void leave(Frame frame, Frame previous, Capture capture) {
        try {
            if (frame != null && CURRENT.get() != frame) disable(capture);
            if (previous == null) CURRENT.remove();
            else CURRENT.set(previous);
        } catch (RuntimeException | Error unavailable) {
            // Carrier cleanup cannot replace an exception from the actual original continuation.
            disable(capture);
        }
    }

    private static ConsumerFrame previousConsumer(Capture capture) {
        try { return CURRENT_CONSUMER.get(); }
        catch (RuntimeException | Error unavailable) { disable(capture); return null; }
    }

    private static ConsumerFrame enterConsumer(Capture capture, Object actualServer, CompletableFuture<?> actualPriorFuture,
            Consumer<?> originalConsumer, Object actualInput, ConsumerFrame previous) {
        try {
            if (!capture.usable || (previous != null && previous.depth >= MAX_CARRIER_DEPTH)) {
                disable(capture); CURRENT_CONSUMER.remove(); return null;
            }
            var frame = new ConsumerFrame(capture, actualServer, actualPriorFuture, originalConsumer, actualInput, previous);
            CURRENT_CONSUMER.set(frame); return frame;
        } catch (RuntimeException | Error unavailable) {
            try { CURRENT_CONSUMER.remove(); }
            catch (RuntimeException | Error cleanupUnavailable) { disable(capture); }
            disable(capture); return null;
        }
    }

    private static void leaveConsumer(ConsumerFrame frame, ConsumerFrame previous, Capture capture) {
        try {
            if (frame != null && CURRENT_CONSUMER.get() != frame) disable(capture);
            if (previous == null) CURRENT_CONSUMER.remove(); else CURRENT_CONSUMER.set(previous);
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
        }
    }

    private static void disable(Capture capture) {
        if (capture != null) capture.usable = false;
    }

    private static void cleanup(Capture capture) {
        if (capture == null) return;
        try {
            synchronized (REGISTRY) {
                if (CAPTURES.get(capture.observation) == capture) CAPTURES.remove(capture.observation);
            }
            capture.usable = false;
            capture.source = null; capture.continuation = null; capture.originalFunction = null;
            capture.originalConsumer = null; capture.consumerPriorFuture = null;
            capture.sourceFuture = null; capture.composedFuture = null; capture.terminalFuture = null;
        } catch (RuntimeException | Error unavailable) {
            disable(capture);
        }
    }

    private static final class Capture {
        private final NativeFunctionLoadObservation observation;
        private final Object server;
        private final Collection<String> selection;
        private volatile boolean usable = true;
        private volatile NativeFunctionLoadObservation.TrackedSupplier<?> source;
        private volatile NativeFunctionLoadObservation.TrackedFunction<?, ?> continuation;
        private volatile Function<?, ?> originalFunction;
        private volatile Consumer<?> originalConsumer;
        private volatile CompletableFuture<?> consumerPriorFuture;
        private volatile CompletableFuture<?> sourceFuture, composedFuture, terminalFuture;
        private boolean composeClaimed, consumerClaimed;
        private Capture(NativeFunctionLoadObservation observation, Object server, Collection<String> selection) {
            this.observation = observation; this.server = server; this.selection = selection;
        }
        private synchronized boolean claimCompose(CompletableFuture<?> actualPriorFuture) {
            if (!usable || composeClaimed || source == null || sourceFuture != actualPriorFuture) {
                usable = false; return false;
            }
            composeClaimed = true; return true;
        }
        private synchronized boolean claimConsumer(CompletableFuture<?> actualPriorFuture) {
            if (!usable || consumerClaimed || !composeClaimed || composedFuture != actualPriorFuture) {
                usable = false; return false;
            }
            consumerClaimed = true; return true;
        }
    }

    private static final class Frame {
        private final Capture capture;
        private final NativeFunctionLoadObservation.TrackedFunction<?, ?> continuation;
        private final CompletableFuture<?> priorFuture;
        private final Function<?, ?> originalFunction;
        private final Object input;
        private final Collection<String> selection;
        private final int depth;
        private final AtomicBoolean managerClaimed = new AtomicBoolean();
        private Frame(Capture capture, NativeFunctionLoadObservation.TrackedFunction<?, ?> continuation,
                CompletableFuture<?> priorFuture, Function<?, ?> originalFunction, Object input, Frame previous) {
            this.capture = capture; this.continuation = continuation; this.priorFuture = priorFuture;
            this.originalFunction = originalFunction; this.input = input; this.selection = capture.selection;
            this.depth = previous == null ? 1 : previous.depth + 1;
        }
    }

    private static final class ConsumerFrame {
        private final Capture capture;
        private final Object server, input;
        private final CompletableFuture<?> priorFuture;
        private final Consumer<?> originalConsumer;
        private final int depth;
        private final AtomicBoolean libraryClaimed = new AtomicBoolean();
        private ConsumerFrame(Capture capture, Object actualServer, CompletableFuture<?> priorFuture,
                Consumer<?> originalConsumer, Object input, ConsumerFrame previous) {
            this.capture = capture; this.server = actualServer; this.priorFuture = priorFuture;
            this.originalConsumer = originalConsumer; this.input = input;
            this.depth = previous == null ? 1 : previous.depth + 1;
        }
    }
}
