// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Bootstrap-owned definitions used by the bounded startup ABI fixture.
 *
 * <p>The source resource is fixture input. Only the native producer's query by
 * each original returned Class supplies observations. This helper accepts no
 * caller Class, source bytes, hash, identity or receipt and grants no target
 * profile or executable closure.
 */
public final class DefinitionStartupFixtures {
    private static final String FIXTURE_NAME =
            "io.github.daejunnom.mmmm.observer.DefinitionStartupProbe";
    private static final String FIXTURE_INTERNAL_NAME =
            "io/github/daejunnom/mmmm/observer/DefinitionStartupProbe";
    private static final String FACTORY_NAME = "ownedRunnable";
    // Exact pinned Javac 25 output for the single lambda in our owned source.
    // Compiler drift fails the fixture rather than discovering another target.
    private static final String LAMBDA_TARGET_NAME = "lambda$ownedRunnable$0";
    private static final byte[] FRAME_MAGIC = "MMMMABI1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] OUTER_MAGIC = "MMMMABI2".getBytes(StandardCharsets.US_ASCII);
    private static final int REQUIRED_STATUS = 255;
    private static final int MAX_PROBE_BYTES = 64 * 1024;
    private static final int MAX_ENVELOPE_BYTES = 8 * 1024 * 1024;
    private static final int MAX_FORWARDER_BYTES = 1024 * 1024;
    private static final int MAX_FRAME_BYTES = 18 * 1024 * 1024;
    private static final int FRAME_HEADER_BYTES = 36;
    private static final int OUTER_HEADER_BYTES = 24;

    private static boolean started;
    private static boolean consumed;
    private static StartupSnapshot ready;

    private DefinitionStartupFixtures() { }

    /** Runs the fixed probes once; a failed attempt is never retried. */
    public static void runOnce() throws IOException, IllegalAccessException {
        synchronized (DefinitionStartupFixtures.class) {
            if (started) throw unavailable("FIXTURE_ALREADY_STARTED");
            started = true;
        }
        requireBootstrap();
        int initialStatus = DefinitionObserverBridge.observedStatus();
        if (initialStatus < 0
                || (initialStatus & DefinitionObserverBridge.INSTALLED) == 0) {
            throw unavailable("PRODUCER_NOT_INSTALLED");
        }
        byte[] input = ownProbeInput();
        Class<?> ordinary = new ProbeLoader().define(input);
        // Preparation of our fixed probe does not initialize it or run a callback.
        ordinary.getDeclaredMethods();
        var ordinaryExecutable = DefinitionObserverBridge.observeCurrentExecutable(ordinary)
                .orElseThrow(() -> unavailable("ORDINARY_OBSERVATION_UNAVAILABLE"));
        var ordinaryObservation = ordinaryExecutable.observation();
        requireObservation(ordinaryObservation, ordinary, false);
        if (ordinaryExecutable.definingLoader() != ordinary.getClassLoader()
                || ordinaryExecutable.definingLoader() == null || ordinaryObservation.definingLoaderIdentity() != 0
                || ordinaryExecutable.sourceInputRole() != DefinitionObserverBridge.SourceInputRole.ORDINARY_HOOK_INPUT) {
            throw unavailable("ORDINARY_ACTUAL_LOADER_UNAVAILABLE");
        }
        // Preserve the raw definition before initializing only this owned class.
        var savedOrdinary = new ClassObservation(ordinaryExecutable);

        Class<?> direct = new ProbeLoader().defineDirect(input);
        direct.getDeclaredMethods();
        requireDirectUnobserved(direct);

        Class<?> hidden = MethodHandles.lookup().defineHiddenClass(input, false).lookupClass();
        hidden.getDeclaredMethods();
        var hiddenExecutable = DefinitionObserverBridge.observeCurrentExecutable(hidden)
                .orElseThrow(() -> unavailable("HIDDEN_OBSERVATION_UNAVAILABLE"));
        var hiddenObservation = hiddenExecutable.observation();
        requireObservation(hiddenObservation, hidden, true);
        if (DefinitionObserverBridge.observeHiddenForwarder(hidden).isPresent()) {
            throw unavailable("SAMLESS_PROBE_HAS_FORWARDER");
        }
        if (ordinary == hidden
                || ordinaryObservation.classIdentity() == hiddenObservation.classIdentity()
                || ordinaryObservation.issuerEpoch() != hiddenObservation.issuerEpoch()) {
            throw unavailable("PROBE_IDENTITIES_DISAGREE");
        }
        Runnable runnable = ownedRunnable(ordinary);
        Class<?> positive = runnable.getClass();
        positive.getDeclaredMethods();
        var positiveExecutable = DefinitionObserverBridge.observeCurrentExecutable(positive)
                .orElseThrow(() -> unavailable("POSITIVE_OBSERVATION_UNAVAILABLE"));
        var positiveObservation = positiveExecutable.observation();
        requireObservation(positiveObservation, positive, true);
        if (positive == hidden || positive == ordinary
                || positiveObservation.classIdentity() == hiddenObservation.classIdentity()
                || positiveObservation.classIdentity() == savedOrdinary.classIdentity
                || positiveObservation.issuerEpoch() != savedOrdinary.issuerEpoch) {
            throw unavailable("POSITIVE_IDENTITIES_DISAGREE");
        }
        var savedPositive = new ClassObservation(positiveExecutable);
        var forwarder = DefinitionObserverBridge.observeHiddenForwarder(positive)
                .orElseThrow(() -> unavailable("POSITIVE_FORWARDER_UNAVAILABLE"));
        requirePositiveForwarder(forwarder, savedPositive, savedOrdinary);
        int observedStatus = requireCurrentStatus();
        var snapshot = new StartupSnapshot(
                savedOrdinary, new ClassObservation(hiddenExecutable), direct,
                new ForwarderObservation(savedPositive, forwarder), observedStatus);
        // A short Java monitor publishes only immutable data. No JNI operation
        // runs while this monitor is held.
        synchronized (DefinitionStartupFixtures.class) {
            ready = snapshot;
        }
    }

    /**
     * Consumes only the completed fixed probes, rechecks their original Class
     * objects, then builds one frame. It cannot be populated from a decoded
     * caller envelope, and consumption is final even when revalidation fails.
     */
    static byte[] takeVerifiedFrame() throws IOException {
        StartupSnapshot snapshot;
        synchronized (DefinitionStartupFixtures.class) {
            if (consumed || ready == null) throw unavailable("FIXTURE_NOT_AVAILABLE");
            consumed = true;
            snapshot = ready;
            ready = null;
        }
        requireBootstrap();
        if (snapshot.status != REQUIRED_STATUS) throw unavailable("SAVED_STATUS_UNSUPPORTED");
        requireCurrentStatus();
        snapshot.ordinary.verifyCurrent();
        snapshot.hidden.verifyCurrent();
        if (DefinitionObserverBridge.observeHiddenForwarder(snapshot.hidden.actualClass).isPresent()) {
            throw unavailable("CURRENT_SAMLESS_PROBE_HAS_FORWARDER");
        }
        requireDirectUnobserved(snapshot.directClass);
        snapshot.positive.verifyCurrent(snapshot.ordinary);
        // Status is rechecked after all JNI observations and before any output.
        requireCurrentStatus();
        byte[] output = outerFrame(snapshot);
        requireCurrentStatus();
        return output;
    }

    private static void requireBootstrap() {
        if (DefinitionStartupFixtures.class.getClassLoader() != null
                || DefinitionObserverBridge.class.getClassLoader() != null
                || DefinitionStartupEvidenceMain.class.getClassLoader() != null
                || ProbeLoader.class.getClassLoader() != null
                || ClassObservation.class.getClassLoader() != null
                || StartupSnapshot.class.getClassLoader() != null
                || ForwarderObservation.class.getClassLoader() != null
                || Runnable.class.getClassLoader() != null) {
            throw unavailable("BOOTSTRAP_IDENTITY_REQUIRED");
        }
    }

    private static Runnable ownedRunnable(Class<?> ordinary) throws IOException {
        try {
            // The Class and method name are fixed by our original probe, never
            // supplied by a caller. invoke initializes only this owned class.
            var factory = ordinary.getMethod(FACTORY_NAME);
            if (factory.getDeclaringClass() != ordinary
                    || factory.getModifiers() != (Modifier.PUBLIC | Modifier.STATIC)
                    || factory.getParameterCount() != 0 || factory.getReturnType() != Runnable.class) {
                throw unavailable("FIXED_FACTORY_METADATA_DISAGREES");
            }
            var target = ordinary.getDeclaredMethod(LAMBDA_TARGET_NAME);
            if (target.getDeclaringClass() != ordinary || !Modifier.isStatic(target.getModifiers())
                    || !target.isSynthetic() || target.getParameterCount() != 0
                    || target.getReturnType() != void.class) {
                throw unavailable("FIXED_TARGET_METADATA_DISAGREES");
            }
            Object returned = factory.invoke(null);
            if (!(returned instanceof Runnable runnable) || !runnable.getClass().isHidden()
                    || runnable.getClass().getClassLoader() != ordinary.getClassLoader()) {
                throw unavailable("FIXED_FACTORY_RESULT_DISAGREES");
            }
            // Runnable.run and the reflected synthetic target are never invoked.
            return runnable;
        } catch (ReflectiveOperationException exception) {
            throw new IOException("MMMM_DEFINITION_STARTUP_FIXED_FACTORY_FAILED", exception);
        }
    }

    private static void requirePositiveForwarder(
            DefinitionObserverBridge.ObservedHiddenForwarder forwarder,
            ClassObservation source, ClassObservation ordinary) {
        requireObservation(forwarder.source(), source.actualClass, true);
        if (forwarder.source().classIdentity() != source.classIdentity
                || forwarder.source().generation() != source.generation
                || forwarder.source().issuerEpoch() != ordinary.issuerEpoch
                || !Arrays.equals(source.envelope, forwarder.source().envelope())
                || forwarder.targetClassIdentity() != ordinary.classIdentity
                || forwarder.targetGeneration() != ordinary.generation
                || !forwarder.recipeClassName().equals(FIXTURE_INTERNAL_NAME + "$$Lambda")
                || !forwarder.interfaceName().equals("java/lang/Runnable")
                || !forwarder.samName().equals("run") || !forwarder.samDescriptor().equals("()V")
                || !forwarder.targetOwner().equals(FIXTURE_INTERNAL_NAME)
                || !forwarder.targetName().equals(LAMBDA_TARGET_NAME)
                || !forwarder.targetDescriptor().equals("()V")
                || forwarder.targetReferenceIsInterface()
                || (forwarder.targetClassStatus() & (2 | 4)) != (2 | 4)
                || (forwarder.targetClassStatus() & 8) != 0) {
            throw unavailable("FIXED_FORWARDER_DISAGREES");
        }
        // PREPARED and INITIALIZED describe the owned factory's target Class.
        // They are not a game initialization policy, SAM dispatch or profile grant.
    }

    private static int requireCurrentStatus() {
        int status = DefinitionObserverBridge.observedStatus();
        if (status != REQUIRED_STATUS) throw unavailable("CURRENT_STATUS_UNSUPPORTED");
        return status;
    }

    private static void requireDirectUnobserved(Class<?> actualClass) {
        if (actualClass.isHidden() || !FIXTURE_NAME.equals(actualClass.getName())
                || DefinitionObserverBridge.observe(actualClass).isPresent()
                || DefinitionObserverBridge.observeCurrentExecutable(actualClass).isPresent()) {
            throw unavailable("DIRECT_PATH_ISSUED_EVIDENCE");
        }
    }

    private static void requireObservation(
            DefinitionObserverBridge.ObservedDefinition observed,
            Class<?> actualClass, boolean hidden) {
        if (observed.actualClass() != actualClass || observed.hidden() != hidden
                || actualClass.isHidden() != hidden
                || observed.classIdentity() == 0 || observed.generation() == 0
                || observed.attempt() == 0 || observed.issuerEpoch() == 0
                || !observed.observedName().equals(actualClass.getName())
                || (!hidden && !FIXTURE_NAME.equals(actualClass.getName()))) {
            throw unavailable("OBSERVED_CLASS_IDENTITY_DISAGREES");
        }
    }

    private static byte[] ownProbeInput() throws IOException {
        try (var stream = DefinitionStartupFixtures.class
                .getResourceAsStream("DefinitionStartupProbe.class")) {
            if (stream == null) throw unavailable("PROBE_RESOURCE_UNAVAILABLE");
            byte[] input = stream.readNBytes(MAX_PROBE_BYTES + 1);
            if (input.length == 0 || input.length > MAX_PROBE_BYTES || stream.read() != -1) {
                throw unavailable("PROBE_INPUT_BOUND");
            }
            return input;
        }
    }

    private static byte[] frame(StartupSnapshot snapshot) throws IOException {
        int size = Math.addExact(FRAME_HEADER_BYTES,
                Math.addExact(snapshot.ordinary.envelope.length, snapshot.hidden.envelope.length));
        if (size > MAX_FRAME_BYTES) throw unavailable("FRAME_BOUND");
        var buffer = new ByteArrayOutputStream(size);
        try (var output = new DataOutputStream(buffer)) {
            output.write(FRAME_MAGIC);
            output.writeShort(1);
            output.writeShort(0);
            output.writeInt(snapshot.status);
            output.writeLong(snapshot.ordinary.issuerEpoch);
            // This is absence of native evidence for the actual direct Class,
            // not absence of that Class or proof of a supported write profile.
            output.writeByte(1);
            output.writeByte(0);
            output.writeShort(0);
            output.writeInt(snapshot.ordinary.envelope.length);
            output.write(snapshot.ordinary.envelope);
            output.writeInt(snapshot.hidden.envelope.length);
            output.write(snapshot.hidden.envelope);
        }
        byte[] bytes = buffer.toByteArray();
        if (bytes.length != size) throw unavailable("FRAME_SIZE_DISAGREES");
        return bytes;
    }

    private static byte[] outerFrame(StartupSnapshot snapshot) throws IOException {
        // ABI1 remains byte-for-byte in its original layout, nested as a sized
        // field. The aggregate cap can reject individually valid large inputs.
        byte[] original = frame(snapshot);
        int size = Math.addExact(OUTER_HEADER_BYTES, Math.addExact(original.length,
                Math.addExact(snapshot.positive.source.envelope.length,
                        snapshot.positive.envelope.length)));
        if (size > MAX_FRAME_BYTES) throw unavailable("OUTER_FRAME_BOUND");
        var buffer = new ByteArrayOutputStream(size);
        try (var output = new DataOutputStream(buffer)) {
            output.write(OUTER_MAGIC);
            output.writeShort(1);
            output.writeShort(0);
            output.writeInt(original.length);
            output.write(original);
            output.writeInt(snapshot.positive.source.envelope.length);
            output.write(snapshot.positive.source.envelope);
            output.writeInt(snapshot.positive.envelope.length);
            output.write(snapshot.positive.envelope);
        }
        byte[] bytes = buffer.toByteArray();
        if (bytes.length != size) throw unavailable("OUTER_FRAME_SIZE_DISAGREES");
        return bytes;
    }

    private static final class ClassObservation {
        private final DefinitionObserverBridge.CurrentLoadedExecutable executable;
        private final Class<?> actualClass;
        private final boolean hidden;
        private final long classIdentity;
        private final long generation;
        private final long attempt;
        private final long issuerEpoch;
        private final byte[] envelope;

        private ClassObservation(DefinitionObserverBridge.CurrentLoadedExecutable executable) {
            this.executable = executable;
            var observed = executable.observation();
            this.actualClass = observed.actualClass();
            this.hidden = observed.hidden();
            this.classIdentity = observed.classIdentity();
            this.generation = observed.generation();
            this.attempt = observed.attempt();
            this.issuerEpoch = observed.issuerEpoch();
            this.envelope = observed.envelope();
            if (envelope.length == 0 || envelope.length > MAX_ENVELOPE_BYTES) {
                throw unavailable("ENVELOPE_BOUND");
            }
            if (executable.definingLoader() != actualClass.getClassLoader()
                    || executable.sourceInputRole() != (hidden ? DefinitionObserverBridge.SourceInputRole.HIDDEN_DEFINE_RECIPE
                                                              : DefinitionObserverBridge.SourceInputRole.ORDINARY_HOOK_INPUT)) {
                throw unavailable("ACTUAL_EXECUTABLE_IDENTITY_CHANGED");
            }
        }

        private void verifyCurrent() {
            if (!executable.isCurrent()) throw unavailable("CURRENT_OBSERVATION_UNAVAILABLE");
            var observed = executable.observation();
            requireObservation(observed, actualClass, hidden);
            if (observed.classIdentity() != classIdentity || observed.generation() != generation
                    || observed.attempt() != attempt || observed.issuerEpoch() != issuerEpoch
                    || executable.actualClass() != actualClass || executable.definingLoader() != actualClass.getClassLoader()
                    || !Arrays.equals(envelope, observed.envelope())) {
                throw unavailable("CURRENT_OBSERVATION_CHANGED");
            }
        }
    }

    private static final class StartupSnapshot {
        private final ClassObservation ordinary;
        private final ClassObservation hidden;
        private final Class<?> directClass;
        private final ForwarderObservation positive;
        private final int status;

        private StartupSnapshot(ClassObservation ordinary, ClassObservation hidden,
                Class<?> directClass, ForwarderObservation positive, int status) {
            this.ordinary = ordinary;
            this.hidden = hidden;
            this.directClass = directClass;
            this.positive = positive;
            this.status = status;
        }
    }

    private static final class ForwarderObservation {
        private final ClassObservation source;
        private final int targetClassStatus;
        private final byte[] envelope;

        private ForwarderObservation(ClassObservation source,
                DefinitionObserverBridge.ObservedHiddenForwarder forwarder) {
            this.source = source;
            this.targetClassStatus = forwarder.targetClassStatus();
            this.envelope = forwarder.envelope();
            if (envelope.length == 0 || envelope.length > MAX_FORWARDER_BYTES) {
                throw unavailable("FORWARDER_BOUND");
            }
        }

        private void verifyCurrent(ClassObservation ordinary) {
            source.verifyCurrent();
            var forwarder = DefinitionObserverBridge.observeHiddenForwarder(source.actualClass)
                    .orElseThrow(() -> unavailable("CURRENT_FORWARDER_UNAVAILABLE"));
            requirePositiveForwarder(forwarder, source, ordinary);
            if (forwarder.targetClassStatus() != targetClassStatus
                    || !Arrays.equals(envelope, forwarder.envelope())) {
                throw unavailable("CURRENT_FORWARDER_CHANGED");
            }
        }
    }

    private static final class ProbeLoader extends ClassLoader {
        private ProbeLoader() { super(null); }
        private Class<?> define(byte[] input) {
            return defineClass(FIXTURE_NAME, input, 0, input.length);
        }
        private Class<?> defineDirect(byte[] input) {
            ByteBuffer buffer = ByteBuffer.allocateDirect(input.length);
            buffer.put(input).flip();
            return defineClass(FIXTURE_NAME, buffer, null);
        }
    }

    private static IllegalStateException unavailable(String reason) {
        return new IllegalStateException("MMMM_DEFINITION_STARTUP_" + reason);
    }
}
