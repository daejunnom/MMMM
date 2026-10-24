// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A bootstrap-loaded read boundary for the in-process Rust JVMTI producer.
 *
 * <p>Only a query by an actual Class object reaches JNI. Neither bytes, names,
 * claimed hashes nor a proposed receipt can register a definition. The producer
 * joins its own definition attempt to the actual returned JNI Class identity.
 * This class checks the bounded binary envelope and preserves all observations;
 * a separate trusted gate must check the closed startup pipeline and semantic
 * executable closure before admitting a parser or command handler.
 */
public final class DefinitionObserverBridge {
    private static final byte[] MAGIC = "MMMMDEF1".getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_EVIDENCE_BYTES = 8 * 1024 * 1024;
    private static final int MAX_TEXT_BYTES = 16 * 1024;
    private static final int MAX_METHODS = 4096;
    private static final byte[] FORWARDER_MAGIC = "MMMMSAM1".getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_FORWARDER_BYTES = 1024 * 1024;
    private static final int MAX_FORWARDER_TEXT_BYTES = 4096;
    private static final int MAX_FORWARDER_REFERENCES = 256;

    public static final int INSTALLED = 1;
    public static final int DEFINE_CLASS_1_BOUND = 2;
    public static final int DEFINE_CLASS_2_BOUND = 4;
    public static final int DEFINE_CLASS_0_BOUND = 8;
    public static final int CLASS_FILE_HOOK_ENABLED = 16;
    public static final int CLASS_PREPARE_ENABLED = 32;
    public static final int EXECUTABLE_READ_CAPABILITIES = 64;
    public static final int VM_LIVE = 128;

    private DefinitionObserverBridge() { }

    /** Actual installed callback/binding facts; these bits grant no profile or write authority. */
    public static int observedStatus() {
        return nativeStatus();
    }

    /**
     * Query a currently observed Class identity. A missing, ambiguous, stale or
     * unsupported definition returns empty. Native failures are not converted
     * to an observed definition or a claim that a class is absent.
     */
    public static Optional<ObservedDefinition> observe(Class<?> actualClass) {
        Objects.requireNonNull(actualClass);
        if (actualClass.isArray() || actualClass.isPrimitive()) return Optional.empty();
        byte[] bytes = nativeEvidence(actualClass);
        return bytes == null ? Optional.empty() : Optional.of(decode(actualClass, bytes));
    }

    /**
     * Acquires a factual view only through the original actual-Class JNI query.
     * This is neither final-classfile evidence nor parser, profile or write admission.
     * A stable empty result means no usable observation, never class absence.
     */
    public static Optional<CurrentLoadedExecutable> observeCurrentExecutable(Class<?> actualClass) {
        Objects.requireNonNull(actualClass);
        if (actualClass.isArray() || actualClass.isPrimitive()) return Optional.empty();
        int before = observedStatus();
        requireCurrentProducer(before, before);
        ClassLoader loader = actualClass.getClassLoader();
        Optional<ObservedDefinition> observed = observe(actualClass);
        int after = observedStatus();
        requireCurrentProducer(before, after);
        if (actualClass.getClassLoader() != loader) throw invalid();
        return observed.map(value -> new CurrentLoadedExecutable(value, loader));
    }

    private static void requireCurrentProducer(int before, int after) {
        int required = INSTALLED | CLASS_FILE_HOOK_ENABLED | CLASS_PREPARE_ENABLED | EXECUTABLE_READ_CAPABILITIES | VM_LIVE;
        if (before < 0 || after != before || (after & required) != required) {
            throw new CurrentObservationException(before, after);
        }
    }

    /** Preserves actual native status without replacing it with an empty observation. */
    public static final class CurrentObservationException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final int beforeStatus;
        private final int afterStatus;
        private CurrentObservationException(int beforeStatus, int afterStatus) {
            super("Native executable observation is unavailable or changed");
            this.beforeStatus = beforeStatus; this.afterStatus = afterStatus;
        }
        public int beforeStatus() { return beforeStatus; }
        public int afterStatus() { return afterStatus; }
    }

    public enum SourceInputRole { ORDINARY_HOOK_INPUT, HIDDEN_DEFINE_RECIPE }

    /**
     * An issuer-acquired Class view, not a caller-created receipt or an authority grant.
     * The CP and method bytes were read by the existing native producer. Revalidation
     * checks that original record; it does not claim another fresh VM snapshot.
     */
    public static final class CurrentLoadedExecutable {
        private final ObservedDefinition observation;
        private final ClassLoader definingLoader;
        private CurrentLoadedExecutable(ObservedDefinition observation, ClassLoader definingLoader) {
            this.observation = observation; this.definingLoader = definingLoader;
        }
        public Class<?> actualClass() { return observation.actualClass(); }
        /** Actual loader object; a decoded numeric loader ID alone cannot issue this view. */
        public ClassLoader definingLoader() { return definingLoader; }
        public ObservedDefinition observation() { return observation; }
        public SourceInputRole sourceInputRole() {
            return observation.hidden() ? SourceInputRole.HIDDEN_DEFINE_RECIPE : SourceInputRole.ORDINARY_HOOK_INPUT;
        }
        public boolean isCurrent() {
            Optional<CurrentLoadedExecutable> current = observeCurrentExecutable(actualClass());
            return current.isPresent() && sameExecutableObservation(observation, definingLoader,
                    current.orElseThrow().observation, current.orElseThrow().definingLoader);
        }
        /** Retained byte-array payload only; VM heap and Java object overhead are separate. */
        public long retainedPayloadBytes() {
            long bytes = (long) observation.envelope.length + observation.terminalObservedBytes.length
                    + observation.hiddenInputBytes.length + observation.constantPoolBytes.length;
            for (ObservedMethod method : observation.methods) bytes += method.bytecodes.length;
            return bytes;
        }
    }

    // Pure comparison is useful for codec regressions, but never constructs the issuer view.
    static boolean sameExecutableObservation(ObservedDefinition original, ClassLoader originalLoader,
                                             ObservedDefinition current, ClassLoader currentLoader) {
        return original.actualClass == current.actualClass && originalLoader == currentLoader
                && original.actualClass.getClassLoader() == originalLoader
                && current.actualClass.getClassLoader() == currentLoader
                && original.issuerEpoch == current.issuerEpoch && original.classIdentity == current.classIdentity
                && original.generation == current.generation && original.attempt == current.attempt
                && Arrays.equals(original.envelope, current.envelope);
    }

    private static native int nativeStatus();
    private static native byte[] nativeEvidence(Class<?> actualClass);
    private static native byte[] nativeHiddenForwarder(Class<?> actualClass);

    /**
     * Query an optional semantic match over this issuer's actual hidden recipe
     * and VM snapshot. An unsupported recipe returns empty while raw observation
     * remains available. This describes a matched static target; it admits no
     * SAM dispatch, referenced-class closure, source policy or write profile.
     */
    public static Optional<ObservedHiddenForwarder> observeHiddenForwarder(Class<?> actualClass) {
        Objects.requireNonNull(actualClass);
        if (!actualClass.isHidden()) return Optional.empty();
        byte[] frame = nativeHiddenForwarder(actualClass);
        if (frame == null) return Optional.empty();
        ObservedDefinition original = observe(actualClass).orElseThrow(DefinitionObserverBridge::invalid);
        ObservedHiddenForwarder result = decodeForwarder(original, frame);
        int status = observedStatus();
        if (status < 0 || (status & VM_LIVE) == 0) throw invalid();
        return Optional.of(result);
    }

    /** Descriptive issuer observation; private construction does not grant source admission. */
    public static final class ObservedHiddenForwarder {
        private final ObservedDefinition source;
        private final long targetIdentity;
        private final long targetGeneration;
        private final int targetClassStatus;
        private final List<String> symbols;
        private final boolean targetReferenceIsInterface;
        private final List<String> referencedClasses;
        private final byte[] envelope;

        private ObservedHiddenForwarder(ObservedDefinition source, long targetIdentity,
                long targetGeneration, int targetClassStatus, List<String> symbols,
                boolean targetReferenceIsInterface, List<String> referencedClasses, byte[] envelope) {
            this.source = source; this.targetIdentity = targetIdentity;
            this.targetGeneration = targetGeneration; this.targetClassStatus = targetClassStatus;
            this.symbols = List.copyOf(symbols); this.targetReferenceIsInterface = targetReferenceIsInterface;
            this.referencedClasses = List.copyOf(referencedClasses); this.envelope = envelope.clone();
        }

        public ObservedDefinition source() { return source; }
        public long targetClassIdentity() { return targetIdentity; }
        public long targetGeneration() { return targetGeneration; }
        /** Actual JVMTI class status; initialization policy remains a separate admission. */
        public int targetClassStatus() { return targetClassStatus; }
        public String recipeClassName() { return symbols.get(0); }
        public String interfaceName() { return symbols.get(1); }
        public String samName() { return symbols.get(2); }
        public String samDescriptor() { return symbols.get(3); }
        public String targetOwner() { return symbols.get(4); }
        public String targetName() { return symbols.get(5); }
        public String targetDescriptor() { return symbols.get(6); }
        /** Recipe reference kind, not an independently admitted interface Class. */
        public boolean targetReferenceIsInterface() { return targetReferenceIsInterface; }
        /** Symbolic references, not proof that their complete actual Class closure was admitted. */
        public List<String> referencedClasses() { return referencedClasses; }
        public byte[] envelope() { return envelope.clone(); }
    }

    // Pure codec tests can supply descriptive fixtures here; only JNI queries
    // reach this path in production. This cannot issue a TargetEvidenceVerifier proof.
    static ObservedHiddenForwarder decodeForwarder(ObservedDefinition original, byte[] frame) {
        Objects.requireNonNull(original); Objects.requireNonNull(frame);
        if (!original.hidden() || !original.actualClass().isHidden()
                || frame.length > MAX_FORWARDER_BYTES) throw invalid();
        try (var reader = new DataInputStream(new ByteArrayInputStream(frame))) {
            if (!Arrays.equals(reader.readNBytes(FORWARDER_MAGIC.length), FORWARDER_MAGIC)
                    || reader.readUnsignedShort() != 1 || reader.readUnsignedShort() != 0) throw invalid();
            long epoch = reader.readLong(), hiddenIdentity = reader.readLong(), hiddenGeneration = reader.readLong();
            long targetIdentity = reader.readLong(), targetGeneration = reader.readLong();
            int targetStatus = reader.readInt();
            if (epoch != original.issuerEpoch() || hiddenIdentity != original.classIdentity()
                    || hiddenGeneration != original.generation() || targetIdentity == 0 || targetGeneration == 0
                    || (targetStatus & 2) == 0 || (targetStatus & ~0x3f) != 0) throw invalid();
            List<String> symbols = new ArrayList<>(7);
            for (int index = 0; index < 7; index++) symbols.add(forwarderText(reader));
            int targetInterface = reader.readUnsignedByte();
            if (targetInterface > 1 || reader.readUnsignedByte() != 0 || reader.readUnsignedShort() != 0) throw invalid();
            long count = Integer.toUnsignedLong(reader.readInt());
            if (count == 0 || count > MAX_FORWARDER_REFERENCES) throw invalid();
            List<String> references = new ArrayList<>((int) count);
            var distinct = new HashSet<String>();
            for (int index = 0; index < count; index++) {
                String name = forwarderText(reader);
                if (!distinct.add(name)) throw invalid();
                references.add(name);
            }
            String recipeBinaryName = symbols.get(0).replace('/', '.');
            if (reader.available() != 0 || !original.observedName().startsWith(recipeBinaryName + "/")
                    || !references.contains(symbols.get(1))
                    || !references.contains(symbols.get(4))) throw invalid();
            return new ObservedHiddenForwarder(original, targetIdentity, targetGeneration, targetStatus,
                    symbols, targetInterface == 1, references, frame);
        } catch (IOException exception) { throw invalid(); }
    }

    private static String forwarderText(DataInputStream reader) throws IOException {
        byte[] value = bytes(reader, MAX_FORWARDER_TEXT_BYTES);
        if (value.length == 0) throw invalid();
        String text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
        if (text.indexOf('\0') >= 0) throw invalid();
        return text;
    }

    /** Immutable observation. Its private constructor is not a source-admission issuer. */
    public static final class ObservedDefinition {
        private final Class<?> actualClass;
        private final int kind;
        private final long classIdentity;
        private final long generation;
        private final long attempt;
        private final long issuerEpoch;
        private final String observedName;
        private final byte[] terminalObservedBytes;
        private final byte[] hiddenInputBytes;
        private final int hiddenFlags;
        private final boolean hiddenInitialize;
        private final long lookupClassIdentity;
        private final long definingLoaderIdentity;
        private final String hiddenRequestedName;
        private final boolean controlledRecipeInterposition;
        private final long constantPoolCount;
        private final byte[] constantPoolBytes;
        private final List<ObservedMethod> methods;
        private final byte[] envelope;

        private ObservedDefinition(Class<?> actualClass, int kind, long classIdentity,
                long generation, long attempt, long issuerEpoch, String observedName,
                byte[] terminalObservedBytes, byte[] hiddenInputBytes, int hiddenFlags,
                boolean hiddenInitialize, long lookupClassIdentity, long definingLoaderIdentity,
                String hiddenRequestedName, boolean controlledRecipeInterposition,
                long constantPoolCount, byte[] constantPoolBytes,
                List<ObservedMethod> methods, byte[] envelope) {
            this.actualClass = actualClass; this.kind = kind; this.classIdentity = classIdentity;
            this.generation = generation; this.attempt = attempt; this.issuerEpoch = issuerEpoch;
            this.observedName = observedName;
            this.terminalObservedBytes = terminalObservedBytes.clone();
            this.hiddenInputBytes = hiddenInputBytes.clone(); this.hiddenFlags = hiddenFlags;
            this.hiddenInitialize = hiddenInitialize; this.lookupClassIdentity = lookupClassIdentity;
            this.definingLoaderIdentity = definingLoaderIdentity;
            this.hiddenRequestedName = hiddenRequestedName;
            this.controlledRecipeInterposition = controlledRecipeInterposition;
            this.constantPoolCount = constantPoolCount;
            this.constantPoolBytes = constantPoolBytes.clone(); this.methods = List.copyOf(methods);
            this.envelope = envelope.clone();
        }

        public Class<?> actualClass() { return actualClass; }
        public boolean hidden() { return kind == 2; }
        public long classIdentity() { return classIdentity; }
        public long generation() { return generation; }
        public long attempt() { return attempt; }
        public long issuerEpoch() { return issuerEpoch; }
        public String observedName() { return observedName; }
        /** Ordinary terminal hook input; finality requires the separate closed-pipeline gate. */
        public byte[] terminalObservedBytes() { return terminalObservedBytes.clone(); }
        /** Actual hidden definition recipe input, never a reconstructed final classfile. */
        public byte[] hiddenInputBytes() { return hiddenInputBytes.clone(); }
        public int hiddenFlags() { return hiddenFlags; }
        public boolean hiddenInitialize() { return hiddenInitialize; }
        public long lookupClassIdentity() { return lookupClassIdentity; }
        public long definingLoaderIdentity() { return definingLoaderIdentity; }
        public String hiddenRequestedName() { return hiddenRequestedName; }
        /** Source-selected private input copy; it preserves bytes and original native parameters. */
        public boolean controlledRecipeInterposition() { return controlledRecipeInterposition; }
        public long constantPoolCount() { return constantPoolCount; }
        public byte[] constantPoolBytes() { return constantPoolBytes.clone(); }
        public List<ObservedMethod> methods() { return methods; }
        public byte[] envelope() { return envelope.clone(); }
    }

    /** The exact native method-table snapshot. Code kind 1/2 denotes native/abstract code. */
    public static final class ObservedMethod {
        private final String name;
        private final String descriptor;
        private final int modifiers;
        private final int codeKind;
        private final byte[] bytecodes;

        private ObservedMethod(String name, String descriptor, int modifiers, int codeKind, byte[] bytecodes) {
            this.name = name; this.descriptor = descriptor; this.modifiers = modifiers;
            this.codeKind = codeKind; this.bytecodes = bytecodes.clone();
        }
        public String name() { return name; }
        public String descriptor() { return descriptor; }
        public int modifiers() { return modifiers; }
        public int codeKind() { return codeKind; }
        public byte[] bytecodes() { return bytecodes.clone(); }
    }

    // Package-private for pure codec tests; production can reach this only after JNI lookup.
    static ObservedDefinition decode(Class<?> actualClass, byte[] envelope) {
        Objects.requireNonNull(actualClass); Objects.requireNonNull(envelope);
        if (envelope.length > MAX_EVIDENCE_BYTES) throw invalid();
        try (var reader = new DataInputStream(new ByteArrayInputStream(envelope))) {
            if (!Arrays.equals(reader.readNBytes(MAGIC.length), MAGIC)) throw invalid();
            int kind = reader.readUnsignedByte(), flags = reader.readUnsignedByte();
            if ((kind != 1 && kind != 2) || (flags != 1 && flags != 3) || reader.readUnsignedShort() != 0) throw invalid();
            long classId = reader.readLong(), generation = reader.readLong();
            long attempt = reader.readLong(), epoch = reader.readLong();
            // u64 native tokens are opaque. Zero is reserved and never a successful definition.
            if (classId == 0 || generation == 0 || attempt == 0 || epoch == 0) throw invalid();
            String name = text(reader);
            byte[] ordinary = bytes(reader, MAX_EVIDENCE_BYTES), hidden = bytes(reader, MAX_EVIDENCE_BYTES);
            int hiddenFlags = reader.readInt(), initialize = reader.readUnsignedByte();
            if (initialize > 1 || reader.readUnsignedByte() != 0 || reader.readUnsignedShort() != 0) throw invalid();
            long lookupId = reader.readLong(), loaderId = reader.readLong();
            String hiddenRequestedName = modifiedUtf8(bytes(reader, MAX_TEXT_BYTES));
            long poolCount = Integer.toUnsignedLong(reader.readInt());
            byte[] pool = bytes(reader, MAX_EVIDENCE_BYTES);
            long count = Integer.toUnsignedLong(reader.readInt());
            if (count == 0 || count > MAX_METHODS || poolCount < 1 || poolCount > 65535 || pool.length == 0) throw invalid();
            List<ObservedMethod> methods = new ArrayList<>((int) count);
            var identities = new HashSet<MethodIdentity>();
            for (int index = 0; index < count; index++) {
                String methodName = text(reader), descriptor = text(reader);
                int modifiers = reader.readInt(), codeKind = reader.readUnsignedByte();
                byte[] code = bytes(reader, MAX_EVIDENCE_BYTES);
                boolean nativeMethod = (modifiers & 0x0100) != 0, abstractMethod = (modifiers & 0x0400) != 0;
                if (codeKind > 2 || nativeMethod && abstractMethod
                        || (codeKind == 0 ? code.length == 0 || nativeMethod || abstractMethod : code.length != 0)
                        || codeKind == 1 && !nativeMethod || codeKind == 2 && !abstractMethod
                        || !identities.add(new MethodIdentity(methodName, descriptor))) throw invalid();
                methods.add(new ObservedMethod(methodName, descriptor, modifiers, codeKind, code));
            }
            if (reader.available() != 0 || actualClass.isHidden() != (kind == 2)
                    || !name.equals(actualClass.getName())
                    || (kind == 1 ? ordinary.length == 0 || hidden.length != 0 || hiddenFlags != 0
                                      || initialize != 0 || lookupId != 0 || !hiddenRequestedName.isEmpty()
                                  : ordinary.length != 0 || hidden.length == 0 || lookupId == 0
                                      || flags != 3 || hiddenRequestedName.isEmpty())) throw invalid();
            return new ObservedDefinition(actualClass, kind, classId, generation, attempt, epoch,
                    name, ordinary, hidden, hiddenFlags, initialize == 1, lookupId, loaderId, hiddenRequestedName,
                    (flags & 2) != 0, poolCount, pool, methods, envelope);
        } catch (IOException exception) { throw invalid(); }
    }

    private record MethodIdentity(String name, String descriptor) { }

    private static byte[] bytes(DataInputStream reader, int limit) throws IOException {
        long length = Integer.toUnsignedLong(reader.readInt());
        if (length > limit || length > reader.available()) throw invalid();
        return reader.readNBytes((int) length);
    }
    private static String text(DataInputStream reader) throws IOException {
        byte[] value = bytes(reader, MAX_TEXT_BYTES);
        if (value.length == 0) throw invalid();
        return modifiedUtf8(value);
    }
    // JNI GetStringUTFChars/GetMethodName preserve UTF-16 code units using
    // Modified UTF-8. In particular, NUL is C0 80 and supplementary characters
    // are two three-byte surrogate units. The original encoding is retained in
    // envelope(); it is never normalized or relabeled as standard UTF-8.
    private static String modifiedUtf8(byte[] value) {
        var result = new StringBuilder(value.length);
        for (int index = 0; index < value.length;) {
            int first = Byte.toUnsignedInt(value[index++]);
            if (first >= 1 && first <= 0x7f) {
                result.append((char) first);
            } else if (first >= 0xc0 && first <= 0xdf) {
                if (index >= value.length) throw invalid();
                int second = Byte.toUnsignedInt(value[index++]);
                if (second < 0x80 || second > 0xbf) throw invalid();
                int unit = (first & 0x1f) << 6 | second & 0x3f;
                if (unit == 0 ? first != 0xc0 || second != 0x80 : unit < 0x80) throw invalid();
                result.append((char) unit);
            } else if (first >= 0xe0 && first <= 0xef) {
                if (value.length - index < 2) throw invalid();
                int second = Byte.toUnsignedInt(value[index++]), third = Byte.toUnsignedInt(value[index++]);
                if (second < 0x80 || second > 0xbf || third < 0x80 || third > 0xbf) throw invalid();
                int unit = (first & 0x0f) << 12 | (second & 0x3f) << 6 | third & 0x3f;
                if (unit < 0x800) throw invalid();
                result.append((char) unit);
            } else {
                throw invalid();
            }
        }
        return result.toString();
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("MMMM_DEFINITION_EVIDENCE_INVALID");
    }
}
