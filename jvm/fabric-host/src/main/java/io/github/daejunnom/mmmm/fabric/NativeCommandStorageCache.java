package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.fabric.mixin.CommandStorageCacheAccessor;
import io.github.daejunnom.mmmm.fabric.mixin.CommandStorageContainerCacheAccessor;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.Map;
import java.util.Objects;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.server.MinecraftServer;
import net.minecraft.world.level.storage.CommandStorage;

/** Actual cached maps only: no native get/load, state creation, source grant or write authority. */
final class NativeCommandStorageCache {
    private static final int MAX_MEMBERS = 4096;
    private static final String CONTAINER = "net.minecraft.world.level.storage.CommandStorage$Container";
    private NativeCommandStorageCache() { }
    enum State { PRESENT, KEY_ABSENT, NAMESPACE_UNKNOWN, NOT_ADMITTED }
    record Facts(State state, CompoundTag cachedRoot) {
        Facts {
            Objects.requireNonNull(state);
            if ((state == State.PRESENT) != (cachedRoot != null)) throw new IllegalArgumentException("Only an observed existing key has a native root");
        }
    }

    /** No callback is retained. This native identity witness lives only until image production ends. */
    static final class Read {
        private final ActualView view;
        private final Snapshot snapshot;
        private Read(ActualView view, Snapshot snapshot) { this.view = view; this.snapshot = snapshot; }
        Facts facts() { return snapshot.facts(); }
        void checkCurrent() { snapshot.checkCurrent(view); }
        void checkComplete(NativeCalibrationStateReader.Checkpoint checkpoint) { snapshot.checkComplete(view, checkpoint); }
    }

    static Read observe(MinecraftServer server, String expected, NativeCalibrationStateReader.Checkpoint checkpoint) {
        Objects.requireNonNull(server); Objects.requireNonNull(checkpoint); checkpoint.check();
        return NativeCalibrationStateReader.checked(() -> {
            ActualView view = new ActualView(server);
            return new Read(view, inspect(view, expected, checkpoint));
        }, checkpoint);
    }

    /** Comparison port. Its Snapshot is data and cannot construct an actual Read or ImagePair. */
    interface View {
        Map<String, ?> namespaces();
        Map<String, CompoundTag> contents(Object container);
        void checkCurrent();
    }

    static final class Snapshot {
        private final String expected, namespace, path;
        private final Map<String, ?> namespaces;
        private final Object container;
        private final Map<String, CompoundTag> contents;
        private final Facts facts;
        private Snapshot(String expected, String namespace, String path, Map<String, ?> namespaces,
                         Object container, Map<String, CompoundTag> contents, Facts facts) {
            this.expected = expected; this.namespace = namespace; this.path = path; this.namespaces = namespaces;
            this.container = container; this.contents = contents; this.facts = facts;
        }
        Facts facts() { return facts; }
        void checkComplete(View view, NativeCalibrationStateReader.Checkpoint checkpoint) {
            NativeCalibrationStateReader.checked(() -> {
                checkCurrent(view);
                Snapshot after = inspect(view, expected, checkpoint);
                if (!sameTarget(after)) throw changed();
                checkCurrent(view); return null;
            }, checkpoint);
        }
        void checkCurrent(View view) {
            view.checkCurrent();
            if (view.namespaces() != namespaces) throw changed();
            if (namespaces == null) return;
            if (namespaces.size() > MAX_MEMBERS) throw limit();
            if (facts.state() == State.NAMESPACE_UNKNOWN) {
                if (namespaces.containsKey(namespace)) throw changed();
                return;
            }
            if (!namespaces.containsKey(namespace) || namespaces.get(namespace) != container) throw changed();
            if (view.contents(container) != contents) throw changed();
            if (contents == null) return;
            if (contents.size() > MAX_MEMBERS) throw limit();
            boolean present = contents.containsKey(path);
            if (facts.state() == State.KEY_ABSENT) { if (present) throw changed(); }
            else if (facts.state() == State.PRESENT && (!present || contents.get(path) != facts.cachedRoot())) throw changed();
        }
        private boolean sameTarget(Snapshot after) {
            return namespaces == after.namespaces && container == after.container && contents == after.contents
                    && facts.state() == after.facts.state() && facts.cachedRoot() == after.facts.cachedRoot();
        }
    }

    static Snapshot inspect(View view, String expected, NativeCalibrationStateReader.Checkpoint checkpoint) {
        Objects.requireNonNull(view); Objects.requireNonNull(checkpoint); checkpoint.check();
        if (expected == null || expected.length() > 256 || !expected.matches("[a-z0-9_.-]+:[a-z0-9/._-]+")) throw changed();
        int separator = expected.indexOf(':'); String namespace = expected.substring(0, separator), path = expected.substring(separator + 1);
        NativeCalibrationStateReader.Checkpoint current = () -> { checkpoint.check(); view.checkCurrent(); };
        return NativeCalibrationStateReader.checked(() -> {
            current.check(); Map<String, ?> namespaces = view.namespaces();
            if (namespaces == null) return new Snapshot(expected, namespace, path, null, null, null, new Facts(State.NOT_ADMITTED, null));
            if (namespaces.size() > MAX_MEMBERS) throw limit();
            int namespaceCount = 0, keyCount = 0; boolean foundNamespace = false;
            Object selectedContainer = null; Map<String, CompoundTag> selectedContents = null;
            for (var entry : namespaces.entrySet()) {
                current.check(); if (++namespaceCount > MAX_MEMBERS) throw limit();
                if (entry.getKey() == null || entry.getValue() == null) throw changed();
                Object container = entry.getValue(); Map<String, CompoundTag> contents = view.contents(container);
                if (contents == null) throw changed();
                int count = 0, size = contents.size();
                if (size > MAX_MEMBERS - keyCount) throw limit();
                for (var item : contents.entrySet()) {
                    current.check(); if (++count > MAX_MEMBERS - keyCount) throw limit();
                    if (item.getKey() == null || item.getValue() == null) throw changed();
                }
                if (count != size || contents.size() != size || view.contents(container) != contents
                        || namespaces.get(entry.getKey()) != container) throw changed();
                keyCount += count;
                if (namespace.equals(entry.getKey())) {
                    if (foundNamespace) throw changed(); foundNamespace = true; selectedContainer = container; selectedContents = contents;
                }
            }
            if (namespaceCount != namespaces.size()) throw changed();
            State state = foundNamespace ? State.KEY_ABSENT : State.NAMESPACE_UNKNOWN; CompoundTag root = null;
            if (foundNamespace && selectedContents.containsKey(path)) {
                root = selectedContents.get(path);
                if (root == null || root.getClass() != CompoundTag.class) throw changed();
                state = State.PRESENT;
            }
            Snapshot result = new Snapshot(expected, namespace, path, namespaces, selectedContainer, selectedContents, new Facts(state, root));
            result.checkCurrent(view); current.check(); return result;
        }, current);
    }

    private static final class ActualView implements View {
        private final MinecraftServer server;
        private final CommandStorage storage;
        private ActualView(MinecraftServer server) { this.server = server; storage = server.getCommandStorage(); }
        @Override public void checkCurrent() {
            if (!server.isSameThread() || server.getCommandStorage() != storage) throw changed();
        }
        @Override public Map<String, ?> namespaces() {
            if (storage == null || storage.getClass() != CommandStorage.class || !(storage instanceof CommandStorageCacheAccessor access)) return null;
            return access.mmmm$namespaces();
        }
        @Override public Map<String, CompoundTag> contents(Object container) {
            if (!CONTAINER.equals(container.getClass().getName()) || container.getClass().getClassLoader() != CommandStorage.class.getClassLoader()
                    || !(container instanceof CommandStorageContainerCacheAccessor access)) return null;
            var source = container.getClass().getProtectionDomain().getCodeSource();
            var admitted = CommandStorage.class.getProtectionDomain().getCodeSource();
            if (source == null || admitted == null || !source.getLocation().equals(admitted.getLocation())) return null;
            return access.mmmm$storage();
        }
    }
    private static ContractException changed() { return new ContractException("CALIBRATION_STATE_CHANGED", "The actual native storage cache changed or is not admitted"); }
    private static ContractException limit() { return new ContractException("CALIBRATION_STATE_LIMIT", "The complete native storage cache membership exceeds its finite limit"); }
}
