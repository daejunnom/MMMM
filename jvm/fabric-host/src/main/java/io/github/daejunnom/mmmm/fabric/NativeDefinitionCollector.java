package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.observer.DefinitionObserverBridge;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** 실제 registry 객체의 관측 원자료만 보관한다. parser/source/profile 승인자는 아니다. */
final class NativeDefinitionCollector implements NativeRegistry.ClassSink {
    static final int MAX_CLASSES = 64;
    static final long MAX_BYTES = 8L * 1024 * 1024;
    @FunctionalInterface interface Checkpoint { void check(); }
    interface ObservationPort {
        RawObservation observe(Class<?> actualClass);
        boolean current(RawObservation original);
    }
    record Limits(int classes, long bytes) {
        Limits {
            if (classes < 1 || classes > MAX_CLASSES || bytes < 0 || bytes > MAX_BYTES) throw new IllegalArgumentException("Collector limits");
        }
    }
    record Stamp(long issuer, long identity, long generation, long attempt, long loader, boolean hidden) { }
    static final class ProducerStateFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;
        ProducerStateFailure(int status) { super("Native observer producer is unavailable or changed"); this.status = status; }
        ProducerStateFailure(DefinitionObserverBridge.CurrentObservationException cause) {
            super("Native observer producer is unavailable or changed", cause); this.status = cause.afterStatus();
        }
    }
    static final class RawObservation {
        private final Class<?> actualClass;
        private final ClassLoader actualLoader;
        private final Stamp stamp;
        private final byte[] envelope;
        private final byte[] forwarder;
        private final DefinitionObserverBridge.CurrentLoadedExecutable executable;
        // A codec/test observation has no issuer view and cannot satisfy executable lookup.
        RawObservation(Class<?> actualClass, Stamp stamp, byte[] envelope, byte[] forwarder) {
            this.actualClass = Objects.requireNonNull(actualClass); this.stamp = Objects.requireNonNull(stamp);
            this.actualLoader = actualClass.getClassLoader(); this.executable = null;
            if (envelope.length == 0 || envelope.length > MAX_BYTES || forwarder.length > 1024 * 1024) throw new ContractException("OBSERVATION_BYTE_LIMIT", "Definition observation exceeds its bound");
            this.envelope = envelope.clone(); this.forwarder = forwarder.clone();
        }
        private RawObservation(DefinitionObserverBridge.CurrentLoadedExecutable executable, byte[] forwarder) {
            this.executable = Objects.requireNonNull(executable);
            this.actualClass = executable.actualClass(); this.actualLoader = executable.definingLoader();
            var observed = executable.observation();
            this.stamp = new Stamp(observed.issuerEpoch(), observed.classIdentity(), observed.generation(),
                    observed.attempt(), observed.definingLoaderIdentity(), observed.hidden());
            // The view already owns the envelope and decoded byte payloads; do not retain another copy.
            this.envelope = null;
            if (executable.retainedPayloadBytes() > MAX_BYTES || forwarder.length > 1024 * 1024) {
                throw new ContractException("OBSERVATION_BYTE_LIMIT", "Definition observation exceeds its bound");
            }
            this.forwarder = forwarder.clone();
        }
        long bytes() { return (executable == null ? (long) envelope.length : executable.retainedPayloadBytes()) + forwarder.length; }
        private byte[] envelope() { return executable == null ? envelope : executable.observation().envelope(); }
        boolean same(RawObservation other) {
            return actualClass == other.actualClass && actualLoader == other.actualLoader && stamp.equals(other.stamp)
                    && (executable == null) == (other.executable == null)
                    && Arrays.equals(envelope(), other.envelope()) && Arrays.equals(forwarder, other.forwarder);
        }
    }
    record Observation(Class<?> actualClass, Set<NativeRegistry.ClassRole> roles, RawObservation raw,
                       String reasonCode, String failureClass, Integer nativeStatus) { }
    record Snapshot(List<Observation> observations, long retainedBytes, long omittedInputs, String overflowReason, String stopReason, boolean completed) {
        boolean hasRawObservation() { return observations.stream().anyMatch(item -> item.raw() != null); }
        DefinitionObserverBridge.CurrentLoadedExecutable executable(Class<?> actualClass) {
            if (!completed || stopReason != null || omittedInputs != 0 || overflowReason != null) return null;
            for (Observation item : observations) {
                if (item.actualClass() == actualClass && item.raw() != null) return item.raw().executable;
            }
            return null;
        }
    }
    private static final class Entry {
        private final Class<?> actualClass;
        private final EnumSet<NativeRegistry.ClassRole> roles = EnumSet.noneOf(NativeRegistry.ClassRole.class);
        private RawObservation raw;
        private String reason;
        private String failure;
        private Integer nativeStatus;
        private Entry(Class<?> actualClass) { this.actualClass = actualClass; }
    }
    private final Limits limits;
    private final Checkpoint control;
    private final ObservationPort port;
    private final IdentityHashMap<Class<?>, Entry> entries = new IdentityHashMap<>();
    private final List<Entry> order = new ArrayList<>();
    private long retainedBytes;
    private long omittedInputs;
    private String stopReason;
    private boolean completed;

    static NativeDefinitionCollector production(Checkpoint control) {
        ObservationPort port;
        try { port = new BridgePort(); }
        catch (LinkageError failure) {
            port = new ObservationPort() {
                @Override public RawObservation observe(Class<?> actualClass) { throw failure; }
                @Override public boolean current(RawObservation original) { return false; }
            };
        }
        return new NativeDefinitionCollector(new Limits(MAX_CLASSES, MAX_BYTES), control, port);
    }
    NativeDefinitionCollector(Limits limits, Checkpoint control, ObservationPort port) {
        this.limits = Objects.requireNonNull(limits); this.control = Objects.requireNonNull(control); this.port = Objects.requireNonNull(port);
    }
    @Override public void checkpoint() {
        if (completed) throw new ContractException("OBSERVATION_CLOSED", "Definition collection already ended");
        try { control.check(); }
        catch (RuntimeException failure) { stopReason = code(failure, "OBSERVATION_CONTROL_FAILED"); throw failure; }
    }
    @Override public void observe(Class<?> actualClass, NativeRegistry.ClassRole role) {
        checkpoint(); Objects.requireNonNull(actualClass); Objects.requireNonNull(role);
        Entry existing = entries.get(actualClass);
        if (existing != null) { existing.roles.add(role); return; }
        if (entries.size() >= limits.classes()) {
            if (omittedInputs != Long.MAX_VALUE) omittedInputs++;
            return;
        }
        Entry entry = new Entry(actualClass); entry.roles.add(role); entries.put(actualClass, entry); order.add(entry);
        try {
            RawObservation raw = port.observe(actualClass);
            checkpoint();
            if (raw == null) entry.reason = "DEFINITION_NOT_OBSERVED";
            else if (raw.actualClass != actualClass || raw.stamp.hidden() != actualClass.isHidden()
                    || raw.stamp.issuer() == 0 || raw.stamp.identity() == 0 || raw.stamp.generation() == 0 || raw.stamp.attempt() == 0) {
                entry.reason = "OBSERVATION_IDENTITY_MISMATCH";
            } else if (raw.bytes() > limits.bytes() - retainedBytes) entry.reason = "OBSERVATION_BYTE_LIMIT";
            else { entry.raw = raw; retainedBytes += raw.bytes(); }
        } catch (LinkageError failure) {
            entry.reason = "OBSERVER_BRIDGE_UNAVAILABLE"; entry.failure = failure.getClass().getName();
        } catch (RuntimeException failure) {
            entry.reason = code(failure, "OBSERVATION_FAILED"); entry.failure = failure.getClass().getName();
            if (failure instanceof ProducerStateFailure state) entry.nativeStatus = state.status;
            if (stopReason != null) throw failure;
        }
        checkpoint();
    }
    void finish() {
        checkpoint();
        for (Entry entry : order) {
            checkpoint();
            if (entry.raw == null) continue;
            try {
                boolean current = port.current(entry.raw);
                checkpoint();
                if (!current) discard(entry, "OBSERVATION_CHANGED", null);
            } catch (LinkageError failure) {
                discard(entry, "OBSERVER_BRIDGE_UNAVAILABLE", failure.getClass().getName());
            } catch (RuntimeException failure) {
                discard(entry, code(failure, "OBSERVATION_RECHECK_FAILED"), failure.getClass().getName());
                if (failure instanceof ProducerStateFailure state) entry.nativeStatus = state.status;
                if (stopReason != null) throw failure;
            }
        }
        checkpoint(); completed = true;
    }
    Snapshot snapshot() {
        List<Observation> observations = new ArrayList<>();
        for (Entry entry : order) observations.add(new Observation(entry.actualClass, Set.copyOf(entry.roles), entry.raw, entry.reason, entry.failure, entry.nativeStatus));
        return new Snapshot(List.copyOf(observations), retainedBytes, omittedInputs,
                omittedInputs == 0 ? null : "OBSERVATION_CLASS_LIMIT", stopReason, completed);
    }
    void stopped(RuntimeException failure) { stopReason = code(failure, "OBSERVATION_FAILED"); completed = false; }
    private void discard(Entry entry, String reason, String failure) {
        retainedBytes -= entry.raw.bytes(); entry.raw = null; entry.reason = reason; entry.failure = failure;
    }
    private static String code(RuntimeException failure, String fallback) {
        if (failure instanceof ProducerStateFailure) return "OBSERVER_NATIVE_UNAVAILABLE";
        if (failure instanceof ContractException contract && contract.code() != null && contract.code().matches("[A-Z][A-Z0-9_]{0,127}")) return contract.code();
        return fallback;
    }
    /** 별도 nested class로 bridge 부재를 관측 실패로 보존하며 JAR/DTO fallback을 두지 않는다. */
    private static final class BridgePort implements ObservationPort {
        @Override public RawObservation observe(Class<?> actualClass) {
            int before = DefinitionObserverBridge.observedStatus();
            if (before < 0 || (before & DefinitionObserverBridge.VM_LIVE) == 0) throw new ProducerStateFailure(before);
            java.util.Optional<DefinitionObserverBridge.CurrentLoadedExecutable> found;
            try { found = DefinitionObserverBridge.observeCurrentExecutable(actualClass); }
            catch (DefinitionObserverBridge.CurrentObservationException failure) { throw new ProducerStateFailure(failure); }
            if (found.isEmpty()) {
                int after = DefinitionObserverBridge.observedStatus();
                if (after != before) throw new ProducerStateFailure(after);
                return null;
            }
            var executable = found.orElseThrow();
            byte[] forwarder = new byte[0];
            if (actualClass.isHidden()) {
                var matched = DefinitionObserverBridge.observeHiddenForwarder(actualClass);
                if (matched.isPresent()) forwarder = matched.orElseThrow().envelope();
            }
            int after = DefinitionObserverBridge.observedStatus();
            if (after != before) throw new ProducerStateFailure(after);
            return new RawObservation(executable, forwarder);
        }
        @Override public boolean current(RawObservation original) {
            if (original.executable == null) return false;
            RawObservation now = observe(original.actualClass);
            return now != null && original.same(now);
        }
    }
}
