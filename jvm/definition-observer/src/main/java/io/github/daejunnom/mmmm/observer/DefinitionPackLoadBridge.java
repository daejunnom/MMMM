package io.github.daejunnom.mmmm.observer;

import java.util.Arrays;
import java.util.Objects;

/** Relays actual loader observations. An opaque native receipt issues no Java authority. */
public final class DefinitionPackLoadBridge {
    private static final int MAX_RECEIPT_BYTES = 64 * 1024;
    private static final int MAX_READ_BYTES = 64 * 1024;
    private DefinitionPackLoadBridge() { }

    /** The private copy is consumed synchronously; no caller buffer is retained. */
    public static byte[] observe(Object actualPrivatePort, byte[] actualReadBytes,
                                 int offset, int length, int phase) {
        Objects.requireNonNull(actualPrivatePort);
        Objects.requireNonNull(actualReadBytes);
        if (DefinitionPackLoadBridge.class.getClassLoader() != null
                || !actualPrivatePort.getClass().getName().equals(
                        "io.github.daejunnom.mmmm.fabric.NativeFunctionLoadObservation$NativeCall")
                || offset < 0 || length < 0 || length > MAX_READ_BYTES
                || offset > actualReadBytes.length - length || phase < 0 || phase > 48) throw invalid();
        byte[] owned = Arrays.copyOfRange(actualReadBytes, offset, offset + length);
        int before = DefinitionObserverBridge.observedStatus();
        if (before < 0 || (before & (DefinitionObserverBridge.INSTALLED | DefinitionObserverBridge.VM_LIVE))
                != (DefinitionObserverBridge.INSTALLED | DefinitionObserverBridge.VM_LIVE)) throw invalid();
        Throwable primary = null;
        byte[] actualReceipt = null;
        try {
            byte[] receipt = nativeObserve(actualPrivatePort, owned, 0, owned.length, phase);
            if (receipt == null || receipt.length == 0 || receipt.length > MAX_RECEIPT_BYTES) throw invalid();
            if (phase >= 47) actualReceipt = receipt.clone();
            return receipt.clone();
        } catch (RuntimeException | Error failure) {
            primary = failure;
            throw failure;
        } finally {
            // A secondary observer failure never rewrites the original native failure graph.
            int after;
            try { after = DefinitionObserverBridge.observedStatus(); }
            catch (RuntimeException | Error failure) {
                if (primary == null) {
                    if (phase >= 47 && actualReceipt != null) throw retainedFailure(actualReceipt, failure);
                    throw failure;
                }
                after = before;
            }
            if (after != before && primary == null) {
                if (phase >= 47 && actualReceipt != null) throw retainedFailure(actualReceipt, invalid());
                throw invalid();
            }
        }
    }

    /** A post-call failure retains the actual bounded native bytes without issuing any witness. */
    public static final class PackObservationFailure extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final transient byte[] actualReceipt;
        private PackObservationFailure(byte[] actual, Throwable cause) {
            super("The native PACK observation failed its current post-check", cause); actualReceipt = actual.clone();
        }
        public byte[] actualReceipt() { return actualReceipt.clone(); }
    }
    private static PackObservationFailure retainedFailure(byte[] actual, Throwable cause) {
        return new PackObservationFailure(actual, cause);
    }

    private static IllegalStateException invalid() {
        return new IllegalStateException("Native pack-load observation is unavailable or changed");
    }

    private static native byte[] nativeObserve(Object actualPrivatePort, byte[] actualReadBytes,
                                               int offset, int length, int phase);
}
