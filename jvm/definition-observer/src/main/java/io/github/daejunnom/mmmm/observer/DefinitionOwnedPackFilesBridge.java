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
 * No consumer handle map survives a call. A kernel-reported uncertain native
 * completion retains its bounded quarantine and is never reported as closed.
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
    private static Receipt call(Object port, byte[] bundle, int operation) {
        Objects.requireNonNull(port); Objects.requireNonNull(bundle);
        if (DefinitionOwnedPackFilesBridge.class.getClassLoader() != null
                || !port.getClass().getName().equals("io.github.daejunnom.mmmm.fabric.NativeCalibrationPackFiles$NativeCall")
                || bundle.length > MAX_FRAME) throw invalid();
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
        if (++nodes[0] > 256 || depth > 128) throw invalid();
        int code = input.readUnsignedByte();
        if (code == 7) {
            NativeFailure primary = failure(input, result, effects, nodes, depth + 1);
            primary.addSuppressed(failure(input, result, effects, nodes, depth + 1)); return primary;
        }
        String name = switch (code) {
            case 1 -> "UNSAFE_SELECTION"; case 2 -> "NATIVE_UNAVAILABLE"; case 3 -> "NATIVE_BUSY";
            case 4 -> "SOURCE_CHANGED"; case 5 -> "NATIVE_IO"; case 6 -> "ORIGINAL_CHECKPOINT";
            case 8 -> "NATIVE_PANIC"; default -> throw invalid();
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
        return failure;
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
    /** Same-handle flush and two-pass exact original-byte verification facts. */
    public record FileFact(String path, long byteLength, String rawSha256) { }
    public record NativeCreateFact(int ntStatus, Integer completionStatus, Long information, Integer closeNativeError) { }

    /** Retains typed native error and actual original Java causes, without paths. */
    public static final class NativeFailure extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final String code;
        private final Integer nativeError;
        private final boolean effectsMayExist;
        private final Receipt completedReceipt;
        private NativeCreateFact nativeCreate;
        private NativeFailure(String code, Integer nativeError, boolean effectsMayExist, Receipt completedReceipt) {
            super("Native owned-file operation did not complete its current checks");
            this.code = code; this.nativeError = nativeError; this.effectsMayExist = effectsMayExist; this.completedReceipt = completedReceipt;
        }
        public String code() { return code; }
        public Integer nativeError() { return nativeError; }
        public boolean effectsMayExist() { return effectsMayExist; }
        public Receipt completedReceipt() { return completedReceipt; }
        public NativeCreateFact nativeCreate() { return nativeCreate; }
    }
    private static native Object[] nativeCall(Object actualPrivateFabricPort, byte[] originalBundle, int operation);
}
