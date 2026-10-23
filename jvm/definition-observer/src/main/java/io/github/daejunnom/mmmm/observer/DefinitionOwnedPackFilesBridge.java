// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * Actual private Fabric port to the installed Rust owned-file consumer. This
 * issues historical file facts only: no source admission, reload or permission.
 * Native retained roots are bounded separately from the single-call consumer.
 * A kernel-reported uncertain native completion retains its bounded quarantine
 * and is never reported as closed.
 */
public final class DefinitionOwnedPackFilesBridge {
    private static final int REQUIRED = DefinitionObserverBridge.INSTALLED
            | DefinitionObserverBridge.DEFINE_CLASS_1_BOUND | DefinitionObserverBridge.DEFINE_CLASS_2_BOUND
            | DefinitionObserverBridge.DEFINE_CLASS_0_BOUND
            | DefinitionObserverBridge.CLASS_FILE_HOOK_ENABLED | DefinitionObserverBridge.CLASS_PREPARE_ENABLED
            | DefinitionObserverBridge.EXECUTABLE_READ_CAPABILITIES | DefinitionObserverBridge.VM_LIVE;
    private static final int MAX_FRAME = 1024 * 1024 + 48 * 280 + 42;
    private DefinitionOwnedPackFilesBridge() { }

    public static Receipt observePackAbsence(Object actualPrivatePort, byte[] originalBundle) {
        return call(actualPrivatePort, originalBundle, 0);
    }
    public static Receipt createNew(Object actualPrivatePort, byte[] originalBundle) {
        return call(actualPrivatePort, originalBundle, 1);
    }
    public static Receipt observeStorageAbsence(Object actualPrivatePort) {
        return call(actualPrivatePort, new byte[0], 2);
    }
    /**
     * An empty locator only. Creating this object issues no native root, source,
     * read or replay authority. Only the native registry can publish this exact
     * object after binding the original actual objects to an actual held root.
     */
    public static RootAnchor newRootAnchor(Object actualServer, Object actualAttempt,
                                           Object actualInvocation, Object actualSealedFiles) {
        return new RootAnchor(actualServer, actualAttempt, actualInvocation, actualSealedFiles);
    }
    public static HeldRootReceipt observeHeldRoot(Object actualPrivatePort) {
        return retainedCall(actualPrivatePort, 3);
    }
    public static HeldRootReceipt retireHeldRoot(Object actualPrivatePort) {
        return retainedCall(actualPrivatePort, 4);
    }
    private static void requirePort(Object port) {
        Objects.requireNonNull(port);
        if (DefinitionOwnedPackFilesBridge.class.getClassLoader() != null
                || !port.getClass().getName().equals("io.github.daejunnom.mmmm.fabric.NativeCalibrationPackFiles$NativeCall")) throw invalid();
    }
    private static Receipt call(Object port, byte[] bundle, int operation) {
        requirePort(port); Objects.requireNonNull(bundle);
        if (bundle.length > MAX_FRAME) throw invalid();
        int status = DefinitionObserverBridge.observedStatus();
        if (status < 0 || (status & REQUIRED) != REQUIRED) throw new NativeFailure("NATIVE_UNAVAILABLE", null, false, null);
        Throwable primary = null;
        Receipt completed = null;
        try {
            completed = decode(nativeCall(port, bundle, operation), operation);
            return completed;
        } catch (RuntimeException | Error failure) { primary = failure; throw failure; }
        finally {
            int after;
            try { after = DefinitionObserverBridge.observedStatus(); }
            catch (RuntimeException | Error failure) {
                if (primary == null) throw failure;
                if (primary != failure) primary.addSuppressed(failure);
                after = status;
            }
            if (after != status) {
                NativeFailure failure = new NativeFailure("NATIVE_CHANGED", null, operation == 1, completed);
                if (primary == null) throw failure;
                primary.addSuppressed(failure);
            }
        }
    }

    private static HeldRootReceipt retainedCall(Object port, int operation) {
        requirePort(port);
        int status = Integer.MIN_VALUE;
        NativeFailure deferredStatus = null;
        try { status = DefinitionObserverBridge.observedStatus(); }
        catch (RuntimeException | Error failure) {
            if (operation != 4) throw failure;
            deferredStatus = new NativeFailure("NATIVE_CHANGED", null, true, null);
            deferredStatus.initCause(failure);
        }
        if (operation != 4 && (status < 0 || (status & REQUIRED) != REQUIRED)) throw new NativeFailure("NATIVE_UNAVAILABLE", null, false, null);
        Throwable primary = deferredStatus;
        HeldRootReceipt completed = null;
        try {
            completed = decodeHeld(nativeCall(port, new byte[0], operation), operation);
            if (deferredStatus != null) { deferredStatus.completedHeldReceipt = completed; throw deferredStatus; }
            return completed;
        } catch (RuntimeException | Error failure) {
            if (deferredStatus != null) {
                if (failure != deferredStatus) deferredStatus.addSuppressed(failure);
                if (completed == null && failure instanceof NativeFailure nativeFailure) deferredStatus.completedHeldReceipt = nativeFailure.completedHeldReceipt;
                primary = deferredStatus; throw deferredStatus;
            }
            primary = failure; throw failure;
        }
        finally {
            int after;
            try { after = DefinitionObserverBridge.observedStatus(); }
            catch (RuntimeException | Error failure) {
                if (primary == null) {
                    NativeFailure changed = new NativeFailure("NATIVE_CHANGED", null, operation == 4, null);
                    changed.completedHeldReceipt = completed; changed.initCause(failure); throw changed;
                }
                if (primary != failure) primary.addSuppressed(failure);
                after = status;
            }
            if (after != status) {
                NativeFailure failure = new NativeFailure("NATIVE_CHANGED", null, operation == 4, null);
                failure.completedHeldReceipt = completed;
                if (primary == null) throw failure;
                primary.addSuppressed(failure);
            }
        }
    }

    private static Receipt decode(Object[] result, int operation) {
        if (result == null || result.length < 1 || result.length > 257 || !(result[0] instanceof byte[] frame)
                || frame.length > 64 * 1024) throw invalid();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(frame))) {
            if (!Arrays.equals(input.readNBytes(8), "MMMMPKR1".getBytes(StandardCharsets.US_ASCII))) throw invalid();
            int effect = input.readUnsignedByte(), status = input.readUnsignedByte();
            if (effect > 1 || status > 1) throw invalid();
            if (status == 1) {
                NativeFailure failure = failure(input, result, effect == 1, new int[] {0}, 0);
                if (input.read() != -1) throw invalid();
                throw failure;
            }
            int count = input.readUnsignedShort();
            if (count != (operation == 1 ? 48 : 0) || effect != (operation == 1 ? 1 : 0) || result.length != 1) throw invalid();
            List<FileFact> files = new ArrayList<>(count);
            String previous = "";
            long total = 0;
            for (int index = 0; index < count; index++) {
                int size = input.readUnsignedShort();
                if (size < 1 || size > 240) throw invalid();
                byte[] bytes = input.readNBytes(size);
                if (bytes.length != size) throw invalid();
                for (byte value : bytes) if (value < 32 || value > 126) throw invalid();
                String path = new String(bytes, StandardCharsets.US_ASCII);
                long length = input.readLong(); byte[] sha = input.readNBytes(32);
                if (path.compareTo(previous) <= 0 || length < 1 || length > 65536 || sha.length != 32) throw invalid();
                total = Math.addExact(total, length);
                if (total > 1024 * 1024) throw invalid();
                files.add(new FileFact(path, length, HexFormat.of().formatHex(sha))); previous = path;
            }
            if (input.read() != -1) throw invalid();
            return new Receipt(files);
        } catch (IOException | ArithmeticException failure) { throw new IllegalStateException("Invalid native owned-file receipt", failure); }
    }
    private static NativeFailure failure(DataInputStream input, Object[] result, boolean effects, int[] nodes, int depth) throws IOException {
        return failure(input, result, effects, nodes, depth, 256, 128);
    }
    private static NativeFailure failure(DataInputStream input, Object[] result, boolean effects, int[] nodes, int depth,
                                         int maxNodes, int maxDepth) throws IOException {
        if (++nodes[0] > maxNodes || depth > maxDepth) throw invalid();
        int code = input.readUnsignedByte();
        if (code == 7) {
            NativeFailure primary = failure(input, result, effects, nodes, depth + 1, maxNodes, maxDepth);
            primary.addSuppressed(failure(input, result, effects, nodes, depth + 1, maxNodes, maxDepth)); return primary;
        }
        String name = switch (code) {
            case 1 -> "UNSAFE_SELECTION"; case 2 -> "NATIVE_UNAVAILABLE"; case 3 -> "NATIVE_BUSY";
            case 4 -> "SOURCE_CHANGED"; case 5 -> "NATIVE_IO"; case 6 -> "ORIGINAL_CHECKPOINT";
            case 8 -> "NATIVE_PANIC"; case 9 -> "NATIVE_LIFETIME_UNAVAILABLE"; case 10 -> "NATIVE_RETAINED_CLOSE"; default -> throw invalid();
        };
        Integer nativeError = code == 5 ? optionalInt(input) : null;
        NativeFailure failure = new NativeFailure(name, nativeError, effects, null);
        if (code == 5) {
            int hasNativeCreate = input.readUnsignedByte();
            if (hasNativeCreate > 1) throw invalid();
            if (hasNativeCreate == 1) {
                int status = input.readInt(); Integer completion = optionalInt(input);
                int hasInformation = input.readUnsignedByte();
                if (hasInformation > 1) throw invalid();
                Long information = hasInformation == 1 ? input.readLong() : null;
                failure.nativeCreate = new NativeCreateFact(status, completion, information, optionalInt(input));
            }
        }
        if (code == 6) {
            int index = input.readUnsignedShort();
            if (index + 1 >= result.length || !(result[index + 1] instanceof Throwable actual)) throw invalid();
            failure.initCause(actual);
        }
        if (code == 9) {
            int kind = input.readUnsignedByte(), length = input.readUnsignedByte();
            if (kind < 1 || kind > 3 || length < 1 || length > 96) throw invalid();
            byte[] operation = input.readNBytes(length);
            if (operation.length != length) throw invalid();
            for (byte value : operation) if (value < 32 || value > 126) throw invalid();
            String observedKind = switch (kind) {
                case 1 -> "unsupported_target"; case 2 -> "native_failure"; case 3 -> "invalid_observation"; default -> throw invalid();
            };
            var fact = new NativeLifetimeFact(observedKind, new String(operation, StandardCharsets.US_ASCII), optionalInt(input), optionalInt(input));
            if (kind == 1 && (!"target".equals(fact.operation()) || fact.status() != null || fact.nativeCode() != null)) throw invalid();
            failure.nativeLifetime = fact;
        }
        if (code == 10) {
            int stage = input.readUnsignedByte(), hasPin = input.readUnsignedByte();
            if (stage < 1 || stage > 3 || hasPin > 1) throw invalid();
            Integer pin = hasPin == 1 ? input.readUnsignedShort() : null;
            if (pin != null && pin >= 66) throw invalid();
            NativeFailure actual = failure(input, result, effects, nodes, depth + 1, maxNodes, maxDepth);
            if (!"NATIVE_IO".equals(actual.code())) throw invalid();
            failure.initCause(actual);
            failure.retainedClose = new RetainedCloseFact(switch (stage) {
                case 1 -> "before_close"; case 2 -> "native_close"; case 3 -> "after_close"; default -> throw invalid();
            }, pin);
        }
        return failure;
    }
    /** Pure bounded metadata decoder; a decoded receipt is never a root locator. */
    static HeldRootReceipt decodeHeld(Object[] result, int operation) {
        if ((operation != 3 && operation != 4) || result == null || result.length < 1 || result.length > 257
                || !(result[0] instanceof byte[] frame) || frame.length > 64 * 1024) throw invalid();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(frame))) {
            if (!Arrays.equals(input.readNBytes(8), "MMMMPKH1".getBytes(StandardCharsets.US_ASCII))
                    || input.readUnsignedByte() != operation) throw invalid();
            int state = input.readUnsignedByte(), grade = input.readUnsignedByte(), identity = input.readUnsignedByte();
            if (state > 8 || grade > 2 || identity > 2) throw invalid();
            var receipt = new HeldRootReceipt(operation, state, grade, identity, input.readUnsignedShort(), input.readUnsignedShort(),
                    input.readUnsignedShort(), input.readUnsignedShort());
            int status = input.readUnsignedByte();
            if (status > 1 || receipt.pins() > 66 || receipt.closed() + receipt.shared() + receipt.uncertain() > receipt.pins()) throw invalid();
            if (state == 0 && (status != 1 || grade != 0 || identity != 0 || receipt.pins() != 0)) throw invalid();
            if (status == 1) {
                NativeFailure failure = failure(input, result, operation == 4, new int[] {0}, 0, 512, 256);
                failure.completedHeldReceipt = receipt;
                if (input.read() != -1) throw invalid();
                throw failure;
            }
            if (result.length != 1 || input.read() != -1) throw invalid();
            return receipt;
        } catch (IOException failure) { throw new IllegalStateException("Invalid native held-root receipt", failure); }
    }
    private static Integer optionalInt(DataInputStream input) throws IOException {
        int present = input.readUnsignedByte(); if (present > 1) throw invalid(); return present == 1 ? input.readInt() : null;
    }
    private static IllegalStateException invalid() { return new IllegalStateException("Invalid native owned-file boundary"); }

    public static final class Receipt {
        private final List<FileFact> files;
        private Receipt(List<FileFact> files) { this.files = List.copyOf(files); }
        public List<FileFact> files() { return files; }
    }
    /** Opaque actual-object binding, not a serializable ID or a public constructor. */
    public static final class RootAnchor {
        private final Object server, attempt, invocation, bundle;
        private RootAnchor(Object server, Object attempt, Object invocation, Object bundle) {
            this.server = Objects.requireNonNull(server); this.attempt = Objects.requireNonNull(attempt);
            this.invocation = Objects.requireNonNull(invocation); this.bundle = Objects.requireNonNull(bundle);
        }
        private Object nativeServer() { return server; }
        private Object nativeAttempt() { return attempt; }
        private Object nativeInvocation() { return invocation; }
        private Object nativeBundle() { return bundle; }
    }
    /** Historical native retention and close facts only; no current-byte or loaded-source claim. */
    public static final class HeldRootReceipt {
        private final int operation, state, grade, identity, pins, closed, shared, uncertain;
        private HeldRootReceipt(int operation, int state, int grade, int identity, int pins, int closed, int shared, int uncertain) {
            this.operation = operation; this.state = state; this.grade = grade; this.identity = identity;
            this.pins = pins; this.closed = closed; this.shared = shared; this.uncertain = uncertain;
        }
        public int operation() { return operation; }
        public String state() {
            return switch (state) {
                case 0 -> "unknown"; case 1 -> "reserved"; case 2 -> "held_unpublished"; case 3 -> "published_partial"; case 4 -> "complete";
                case 5 -> "retiring"; case 6 -> "reference_released"; case 7 -> "close_uncertain"; case 8 -> "vm_owned";
                default -> throw invalid();
            };
        }
        public String evidenceGrade() {
            return switch (grade) { case 0 -> "unknown"; case 1 -> "windows_create_handle"; case 2 -> "posix_cooperative"; default -> throw invalid(); };
        }
        public String identity() {
            return switch (identity) { case 0 -> "not_observed"; case 1 -> "same"; case 2 -> "different"; default -> throw invalid(); };
        }
        public int pins() { return pins; }
        public int closed() { return closed; }
        public int shared() { return shared; }
        public int uncertain() { return uncertain; }
    }
    /** Same-handle flush and two-pass exact original-byte verification facts. */
    public record FileFact(String path, long byteLength, String rawSha256) { }
    public record NativeCreateFact(int ntStatus, Integer completionStatus, Long information, Integer closeNativeError) { }
    public record NativeLifetimeFact(String kind, String operation, Integer status, Integer nativeCode) { }
    /** The underlying typed native I/O cause remains on NativeFailure.getCause(). */
    public record RetainedCloseFact(String stage, Integer pin) { }

    /** Retains typed native error and actual original Java causes, without paths. */
    public static final class NativeFailure extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final String code;
        private final Integer nativeError;
        private final boolean effectsMayExist;
        private final transient Receipt completedReceipt;
        private transient HeldRootReceipt completedHeldReceipt;
        private transient NativeCreateFact nativeCreate;
        private transient NativeLifetimeFact nativeLifetime;
        private transient RetainedCloseFact retainedClose;
        private NativeFailure(String code, Integer nativeError, boolean effectsMayExist, Receipt completedReceipt) {
            super("Native owned-file operation did not complete its current checks");
            this.code = code; this.nativeError = nativeError; this.effectsMayExist = effectsMayExist; this.completedReceipt = completedReceipt;
        }
        public String code() { return code; }
        public Integer nativeError() { return nativeError; }
        public boolean effectsMayExist() { return effectsMayExist; }
        public Receipt completedReceipt() { return completedReceipt; }
        public HeldRootReceipt completedHeldReceipt() { return completedHeldReceipt; }
        public NativeCreateFact nativeCreate() { return nativeCreate; }
        public NativeLifetimeFact nativeLifetime() { return nativeLifetime; }
        public RetainedCloseFact retainedClose() { return retainedClose; }
    }
    private static native Object[] nativeCall(Object actualPrivateFabricPort, byte[] originalBundle, int operation);
}
