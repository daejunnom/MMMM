package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.observer.DefinitionObserverBridge;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * 실제 선택 객체의 현재 native executable 자료만 보존한다. 선택 경로의 인과는 호출하는
 * function observer가 소유하며, 이 witness는 SourceAdmission/profile/실행 권한이 아니다.
 * 원 ClassPrepare snapshot의 현재 record를 검사한다. 새 VM snapshot이나 최종 classfile을
 * 취득했다고 주장하지 않고 loaded_definition_bytes 또는 definitionSha256로 바꾸지 않는다.
 */
final class NativeCalibrationExecutables {
    static final String SOURCE_KIND = "current_vm_executable";
    static final int MAX_SELECTIONS = 256;
    static final int MAX_CLASSES = 64;
    // Native byte-array payload only. Referenced receiver/capture graphs, reflection objects and
    // VM heap overhead are separate; no captured object graph is copied or claimed immutable.
    static final long MAX_RETAINED_BYTES = 8L * 1024 * 1024;
    private static final int MAX_METHODS = 4096;

    private NativeCalibrationExecutables() { }

    enum Role { PARSER, PREDICATE, HANDLER, REDIRECT }
    enum Status { UNSUPPORTED, UNAVAILABLE, CHANGED, LIMIT }
    enum Reason {
        SELECTION_LIMIT, CLASS_LIMIT, BYTE_LIMIT, RECEIVER_METHOD_MISMATCH,
        NON_PUBLIC_VIRTUAL_METHOD, VIRTUAL_DESCRIPTOR_CHANGED, BRIDGE_OR_SYNTHETIC_METHOD,
        NON_EXECUTABLE_METHOD, METADATA_UNAVAILABLE, NATIVE_OBSERVER_FAILED, CLASS_NOT_OBSERVED, NATIVE_RECORD_CHANGED,
        METHOD_TABLE_MISMATCH, HIDDEN_RECIPE_UNSUPPORTED, HIDDEN_SAM_MISMATCH,
        HIDDEN_INTERFACE_MISMATCH, HIDDEN_TARGET_UNAVAILABLE, HIDDEN_TARGET_IDENTITY_CHANGED,
        HIDDEN_TARGET_METHOD_UNSUPPORTED, HIDDEN_TARGET_ACCESS_UNSUPPORTED
    }

    static final class Failure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final Status status;
        private final Reason reason;
        private Failure(Status status, Reason reason, Throwable cause) {
            super("Selected native executable observation: " + reason.name(), cause);
            this.status = status; this.reason = reason;
        }
        Status status() { return status; }
        Reason reason() { return reason; }
    }

    /** Actual selection inputs, not an assertion that the supplied method was selected by the game. */
    record Selection(Object actualReceiver, Method selectedMethod, Role role) {
        Selection {
            Objects.requireNonNull(actualReceiver); Objects.requireNonNull(selectedMethod); Objects.requireNonNull(role);
        }
    }
    @FunctionalInterface interface Current { void check(); }

    static final class Fact {
        private final Selection selection;
        private final Method implementation;
        private final HiddenLink hidden;
        private Fact(Selection selection, Method implementation, HiddenLink hidden) {
            this.selection = selection; this.implementation = implementation; this.hidden = hidden;
        }
        Role role() { return selection.role(); }
        Object actualReceiver() { return selection.actualReceiver(); }
        Method selectedMethod() { return selection.selectedMethod(); }
        Method implementation() { return implementation; }
        /**
         * Only the original native zero-capture static-forwarder recipe can populate this.
         * Null on an actual hidden receiver means that its target/captured state is unobserved;
         * the exact SAM body remains a factual current_vm_executable, never target admission.
         */
        Method hiddenStaticTarget() { return hidden == null ? null : hidden.target; }
        byte[] hiddenForwarderEnvelope() { return hidden == null ? new byte[0] : hidden.envelope.clone(); }
    }

    static final class Witness {
        private final List<Fact> facts;
        private final IdentityHashMap<Class<?>, DefinitionObserverBridge.CurrentLoadedExecutable> classes;
        private final IdentityHashMap<Class<?>, HiddenLink> hidden;
        private final List<DefinitionObserverBridge.CurrentLoadedExecutable> views;
        private final long retainedBytes;
        private Witness(Builder builder) {
            facts = List.copyOf(builder.facts); classes = new IdentityHashMap<>(builder.classes);
            hidden = new IdentityHashMap<>(builder.hidden); views = List.copyOf(builder.views); retainedBytes = builder.retainedBytes;
        }
        List<Fact> facts() { return facts; }
        /** Immutable factual views in acquisition order, never a registration or bearer grant. */
        List<DefinitionObserverBridge.CurrentLoadedExecutable> executableViews() { return views; }
        int actualClassCount() { return classes.size(); }
        long retainedPayloadBytes() { return retainedBytes; }
        /** Callback is supplied by the current original request and is never retained here. */
        void checkCurrent(Current current) {
            Objects.requireNonNull(current);
            checked(current, () -> {
                recheckClasses(classes, current);
                for (Fact fact : facts) {
                    current.check();
                    Method actual = resolveVirtual(fact.selection, fact.actualReceiver().getClass().isHidden());
                    if (!actual.equals(fact.implementation)) throw failure(Status.CHANGED, Reason.RECEIVER_METHOD_MISMATCH);
                }
                for (var entry : hidden.entrySet()) {
                    current.check();
                    if (entry.getValue() != null) entry.getValue().check(entry.getKey(), classes, current);
                }
                recheckClasses(classes, current);
                return null;
            });
        }
    }

    static Witness acquire(List<Selection> selections, Current current) {
        Objects.requireNonNull(selections); Objects.requireNonNull(current);
        return checked(current, () -> {
            if (selections.isEmpty() || selections.size() > MAX_SELECTIONS) throw failure(Status.LIMIT, Reason.SELECTION_LIMIT);
            List<Selection> original = List.copyOf(selections);
            Builder builder = new Builder();
            for (Selection selection : original) {
                current.check();
                Class<?> receiver = selection.actualReceiver().getClass();
                Method implementation = resolveVirtual(selection, receiver.isHidden());
                builder.view(receiver, current);
                builder.view(implementation.getDeclaringClass(), current);
                requireMethod(builder.classes.get(implementation.getDeclaringClass()), implementation, current);
                HiddenLink hidden = null;
                if (receiver.isHidden()) {
                    HiddenLink link = builder.hidden.get(receiver);
                    if (!builder.hidden.containsKey(receiver)) {
                        link = acquireHidden(receiver, implementation, builder, current);
                        builder.hidden.put(receiver, link);
                    }
                    if (link != null) link.requireSam(implementation);
                    hidden = link;
                }
                builder.facts.add(new Fact(selection, implementation, hidden));
            }
            Witness result = new Witness(builder);
            result.checkCurrent(current);
            return result;
        });
    }

    /** Pure reflection resolution is separately testable; it cannot construct an acquired witness. */
    static Method resolveVirtual(Selection selection, boolean hiddenReceiver) {
        Class<?> receiver = selection.actualReceiver().getClass(); Method selected = selection.selectedMethod();
        if (hiddenReceiver != receiver.isHidden() || !selected.getDeclaringClass().isInstance(selection.actualReceiver())) {
            throw failure(Status.UNSUPPORTED, Reason.RECEIVER_METHOD_MISMATCH);
        }
        if (!Modifier.isPublic(selected.getModifiers()) || Modifier.isStatic(selected.getModifiers())) {
            throw failure(Status.UNSUPPORTED, Reason.NON_PUBLIC_VIRTUAL_METHOD);
        }
        Method implementation;
        try { implementation = receiver.getMethod(selected.getName(), selected.getParameterTypes()); }
        catch (NoSuchMethodException cause) {
            throw new Failure(Status.UNSUPPORTED, Reason.RECEIVER_METHOD_MISMATCH, cause);
        }
        catch (SecurityException | LinkageError cause) { throw new Failure(Status.UNAVAILABLE, Reason.METADATA_UNAVAILABLE, cause); }
        if (!descriptor(selected).equals(descriptor(implementation))) {
            // getMethod prefers the covariant return. The actual erased dispatch instead reaches
            // its bridge: retain that exact method and its native bytes, never silently skip it.
            Method bridge = null;
            Method[] declared = implementation.getDeclaringClass().getDeclaredMethods();
            if (declared.length > MAX_METHODS) throw failure(Status.LIMIT, Reason.METHOD_TABLE_MISMATCH);
            for (Method candidate : declared) if (candidate.isBridge() && candidate.getName().equals(selected.getName())
                    && descriptor(candidate).equals(descriptor(selected))) {
                if (bridge != null) throw failure(Status.UNSUPPORTED, Reason.VIRTUAL_DESCRIPTOR_CHANGED);
                bridge = candidate;
            }
            if (bridge == null) throw failure(Status.UNSUPPORTED, Reason.VIRTUAL_DESCRIPTOR_CHANGED);
            implementation = bridge;
        }
        int flags = implementation.getModifiers();
        if (!Modifier.isPublic(flags) || Modifier.isStatic(flags)) throw failure(Status.UNSUPPORTED, Reason.NON_PUBLIC_VIRTUAL_METHOD);
        if (Modifier.isNative(flags) || Modifier.isAbstract(flags)) throw failure(Status.UNSUPPORTED, Reason.NON_EXECUTABLE_METHOD);
        if (!hiddenReceiver && implementation.isSynthetic() && !implementation.isBridge()) {
            throw failure(Status.UNSUPPORTED, Reason.BRIDGE_OR_SYNTHETIC_METHOD);
        }
        if (hiddenReceiver && implementation.getDeclaringClass() != receiver) throw failure(Status.UNSUPPORTED, Reason.HIDDEN_SAM_MISMATCH);
        return implementation;
    }

    private static HiddenLink acquireHidden(Class<?> receiver, Method sam, Builder builder, Current current) {
        // Every selected hidden SAM already has its actual receiver, exact method-table entry and
        // issuer-acquired current Class envelope above. A captured/other recipe may have no matched
        // static target. Preserve that exact body fact without reading fields or claiming capture
        // values, virtual-target equivalence or closure. The function observer must still bind the
        // same compiled entry/context/receiver to its actual execution-stage observations.
        var matched = queryForwarder(receiver, current);
        if (matched.isEmpty()) return null;
        // Only the existing native zero-capture, one-SAM direct-static matcher can add target facts.
        // This join still admits neither dispatch nor all symbolic referenced-class semantics.
        var forwarder = matched.orElseThrow();
        sameSource(builder.classes.get(receiver), forwarder.source(), current);
        if (!sam.getName().equals(forwarder.samName()) || !descriptor(sam).equals(forwarder.samDescriptor())) {
            throw failure(Status.UNSUPPORTED, Reason.HIDDEN_SAM_MISMATCH);
        }
        Class<?>[] interfaces = receiver.getInterfaces();
        if (interfaces.length != 1 || !interfaces[0].getName().equals(binaryName(forwarder.interfaceName()))) {
            throw failure(Status.UNSUPPORTED, Reason.HIDDEN_INTERFACE_MISMATCH);
        }
        Class<?> targetClass = checked(current, () -> {
            try { return Class.forName(binaryName(forwarder.targetOwner()), false, receiver.getClassLoader()); }
            catch (ClassNotFoundException | LinkageError | SecurityException cause) {
                throw new Failure(Status.UNAVAILABLE, Reason.HIDDEN_TARGET_UNAVAILABLE, cause);
            }
        });
        var targetView = builder.view(targetClass, current);
        if (targetClass.isHidden() || targetClass.isInterface() != forwarder.targetReferenceIsInterface()
                || targetView.observation().classIdentity() != forwarder.targetClassIdentity()
                || targetView.observation().generation() != forwarder.targetGeneration()
                || targetView.observation().issuerEpoch() != forwarder.source().issuerEpoch()) {
            throw failure(Status.CHANGED, Reason.HIDDEN_TARGET_IDENTITY_CHANGED);
        }
        Method target = declaredTarget(targetClass, forwarder.targetName(), forwarder.targetDescriptor(), current);
        int flags = target.getModifiers();
        if (!Modifier.isStatic(flags) || Modifier.isAbstract(flags) || Modifier.isNative(flags) || target.isBridge()) {
            throw failure(Status.UNSUPPORTED, Reason.HIDDEN_TARGET_METHOD_UNSUPPORTED);
        }
        if ((!Modifier.isPublic(flags) || !Modifier.isPublic(targetClass.getModifiers()))
                && (receiver.getNestHost() != targetClass.getNestHost()
                    || receiver.getClassLoader() != targetClass.getClassLoader())) {
            throw failure(Status.UNSUPPORTED, Reason.HIDDEN_TARGET_ACCESS_UNSUPPORTED);
        }
        requireMethod(targetView, target, current);
        byte[] envelope = forwarder.envelope(); builder.charge(envelope.length);
        // Do not retain forwarder.source(): it duplicates the view's decoded payload. The exact
        // forwarder envelope plus the two issuer-acquired Class views are the retained factual pins.
        return new HiddenLink(sam.getName(), descriptor(sam), target, envelope);
    }

    private static final class HiddenLink {
        private final String samName;
        private final String samDescriptor;
        private final Method target;
        private final byte[] envelope;
        private HiddenLink(String samName, String samDescriptor, Method target, byte[] envelope) {
            this.samName = samName; this.samDescriptor = samDescriptor; this.target = target; this.envelope = envelope;
        }
        void requireSam(Method sam) {
            if (!samName.equals(sam.getName()) || !samDescriptor.equals(descriptor(sam))) throw failure(Status.CHANGED, Reason.HIDDEN_SAM_MISMATCH);
        }
        void check(Class<?> receiver, IdentityHashMap<Class<?>, DefinitionObserverBridge.CurrentLoadedExecutable> classes, Current current) {
            var observed = observeForwarder(receiver, current);
            sameSource(classes.get(receiver), observed.source(), current);
            sameBytes(envelope, observed.envelope(), current);
            var targetView = classes.get(target.getDeclaringClass());
            if (targetView == null || observed.targetClassIdentity() != targetView.observation().classIdentity()
                    || observed.targetGeneration() != targetView.observation().generation()) {
                throw failure(Status.CHANGED, Reason.HIDDEN_TARGET_IDENTITY_CHANGED);
            }
            requireMethod(targetView, target, current);
        }
    }

    private static final class Builder {
        private final List<Fact> facts = new ArrayList<>();
        private final IdentityHashMap<Class<?>, DefinitionObserverBridge.CurrentLoadedExecutable> classes = new IdentityHashMap<>();
        private final IdentityHashMap<Class<?>, HiddenLink> hidden = new IdentityHashMap<>();
        private final List<DefinitionObserverBridge.CurrentLoadedExecutable> views = new ArrayList<>();
        private long retainedBytes;
        void charge(long bytes) {
            if (bytes < 0 || bytes > MAX_RETAINED_BYTES - retainedBytes) throw failure(Status.LIMIT, Reason.BYTE_LIMIT);
            retainedBytes += bytes;
        }
        DefinitionObserverBridge.CurrentLoadedExecutable view(Class<?> actual, Current current) {
            var existing = classes.get(actual); if (existing != null) return existing;
            if (classes.size() == MAX_CLASSES) throw failure(Status.LIMIT, Reason.CLASS_LIMIT);
            var acquired = checked(current, () -> {
                try { return DefinitionObserverBridge.observeCurrentExecutable(actual).orElseThrow(() -> failure(Status.UNAVAILABLE, Reason.CLASS_NOT_OBSERVED)); }
                catch (Failure failure) { throw failure; }
                catch (RuntimeException | LinkageError cause) { throw new Failure(Status.UNAVAILABLE, Reason.NATIVE_OBSERVER_FAILED, cause); }
            });
            if (acquired.actualClass() != actual || acquired.definingLoader() != actual.getClassLoader()) throw failure(Status.CHANGED, Reason.NATIVE_RECORD_CHANGED);
            charge(acquired.retainedPayloadBytes()); classes.put(actual, acquired); views.add(acquired); return acquired;
        }
    }

    private static DefinitionObserverBridge.ObservedHiddenForwarder observeForwarder(Class<?> receiver, Current current) {
        return queryForwarder(receiver, current).orElseThrow(() -> failure(Status.CHANGED, Reason.HIDDEN_RECIPE_UNSUPPORTED));
    }
    private static Optional<DefinitionObserverBridge.ObservedHiddenForwarder> queryForwarder(Class<?> receiver, Current current) {
        return checked(current, () -> {
            try { return DefinitionObserverBridge.observeHiddenForwarder(receiver); }
            catch (Failure failure) { throw failure; }
            catch (RuntimeException | LinkageError cause) { throw new Failure(Status.UNAVAILABLE, Reason.NATIVE_OBSERVER_FAILED, cause); }
        });
    }
    private static void recheckClasses(IdentityHashMap<Class<?>, DefinitionObserverBridge.CurrentLoadedExecutable> classes, Current current) {
        for (var entry : classes.entrySet()) checked(current, () -> {
            boolean valid;
            try { valid = entry.getValue().isCurrent(); }
            catch (RuntimeException | LinkageError cause) { throw new Failure(Status.UNAVAILABLE, Reason.NATIVE_OBSERVER_FAILED, cause); }
            if (!valid || entry.getValue().actualClass() != entry.getKey()
                    || entry.getValue().definingLoader() != entry.getKey().getClassLoader()) throw failure(Status.CHANGED, Reason.NATIVE_RECORD_CHANGED);
            return null;
        });
    }
    private static void requireMethod(DefinitionObserverBridge.CurrentLoadedExecutable view, Method method, Current current) {
        if (view == null || view.actualClass() != method.getDeclaringClass()) throw failure(Status.CHANGED, Reason.METHOD_TABLE_MISMATCH);
        String descriptor = descriptor(method); int matches = 0;
        for (var nativeMethod : view.observation().methods()) {
            current.check();
            if (nativeMethod.name().equals(method.getName()) && nativeMethod.descriptor().equals(descriptor)) {
                if (nativeMethod.modifiers() != method.getModifiers() || nativeMethod.codeKind() != 0) throw failure(Status.CHANGED, Reason.METHOD_TABLE_MISMATCH);
                matches++;
            }
        }
        if (matches != 1) throw failure(Status.CHANGED, Reason.METHOD_TABLE_MISMATCH);
    }
    private static Method declaredTarget(Class<?> actual, String name, String descriptor, Current current) {
        Method[] methods = actual.getDeclaredMethods();
        if (methods.length > MAX_METHODS) throw failure(Status.LIMIT, Reason.METHOD_TABLE_MISMATCH);
        Method found = null;
        for (Method method : methods) {
            current.check();
            if (method.getName().equals(name) && descriptor(method).equals(descriptor)) {
                if (found != null) throw failure(Status.UNSUPPORTED, Reason.HIDDEN_TARGET_METHOD_UNSUPPORTED);
                found = method;
            }
        }
        if (found == null) throw failure(Status.UNSUPPORTED, Reason.HIDDEN_TARGET_METHOD_UNSUPPORTED);
        return found;
    }
    static String descriptor(Method method) {
        StringBuilder descriptor = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) descriptor.append(parameter.descriptorString());
        return descriptor.append(')').append(method.getReturnType().descriptorString()).toString();
    }
    private static String binaryName(String internal) { return internal.replace('/', '.'); }
    private static void sameSource(DefinitionObserverBridge.CurrentLoadedExecutable view,
                                   DefinitionObserverBridge.ObservedDefinition source, Current current) {
        var original = view.observation();
        if (source.actualClass() != view.actualClass() || source.actualClass().getClassLoader() != view.definingLoader()
                || source.issuerEpoch() != original.issuerEpoch() || source.classIdentity() != original.classIdentity()
                || source.generation() != original.generation() || source.attempt() != original.attempt()
                || source.definingLoaderIdentity() != original.definingLoaderIdentity()) throw failure(Status.CHANGED, Reason.NATIVE_RECORD_CHANGED);
        sameBytes(original.envelope(), source.envelope(), current);
    }
    private static void sameBytes(byte[] left, byte[] right, Current current) {
        if (left.length != right.length) throw failure(Status.CHANGED, Reason.NATIVE_RECORD_CHANGED);
        for (int index = 0; index < left.length; index++) {
            if ((index & 65535) == 0) current.check();
            if (left[index] != right[index]) throw failure(Status.CHANGED, Reason.NATIVE_RECORD_CHANGED);
        }
        current.check();
    }
    private static Failure failure(Status status, Reason reason) { return new Failure(status, reason, null); }
    /** Native/reflection failure remains primary if the same original request also stops. */
    private static <T> T checked(Current current, Supplier<T> action) {
        current.check(); Throwable original = null;
        try { return action.get(); }
        catch (RuntimeException | Error failure) { original = failure; throw failure; }
        finally {
            try { current.check(); }
            catch (RuntimeException | Error post) {
                if (original == null) throw post;
                if (post != original) original.addSuppressed(post);
            }
        }
    }
}
