package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.javaadapter.AdapterLimits;
import io.github.daejunnom.mmmm.javaadapter.ApprovedArtifact;
import io.github.daejunnom.mmmm.javaadapter.CompatibilityInterfaceProbe;
import io.github.daejunnom.mmmm.javaadapter.PublicJavaAdapter;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.metadata.ModOrigin;

/** Ordinary input-JAR and actual public-class metadata only; never a loaded-definition or execution issuer. */
final class NativeCompatibilityMetadataResolver implements NativeCompatibilityApprovals.MetadataTargetResolver, AutoCloseable {
    private static final long MAX_SNAPSHOT_BYTES = AdapterLimits.EXPANDED_BYTES;
    private static final long MAX_SCOPE_READ_BYTES = AdapterLimits.EXPANDED_BYTES;
    private final ObjectNode environment;
    private final String generation;
    private final String gameVersion;
    private final ClassLoader actualLoader;
    private final Runnable currentHost;
    private final ModLookup mods;
    private final Map<String, Profile> profiles = new LinkedHashMap<>();
    private final Map<Path, Snapshot> snapshots = new LinkedHashMap<>();
    private final Map<String, ModIdentity> resolvedMods = new LinkedHashMap<>();
    private long retainedBytes;
    private Scope active;
    private boolean closed;

    /** Testable metadata seam; the production implementation below obtains these values from Fabric. */
    record ModIdentity(String modId, String version, Path jar) { }
    @FunctionalInterface interface ModLookup { ModIdentity find(String modId, Runnable checkpoint); }
    private record Profile(NativeCompatibilityApprovals.ApprovedProfile approval, String modId) { }
    private record Snapshot(Path path, BasicFileAttributes identity, ApprovedArtifact artifact) { }
    private static final class Use {
        final Snapshot snapshot;
        final Map<String, ModIdentity> mods = new LinkedHashMap<>();
        Use(Snapshot snapshot) { this.snapshot = snapshot; }
    }
    private static final class Scope {
        final Runnable control;
        final Map<Path, Use> used = new LinkedHashMap<>();
        long reservedReadBytes;
        boolean sourcesChecked;
        Scope(Runnable control) { this.control = control; }
    }

    NativeCompatibilityMetadataResolver(ContractJson contracts, List<NativeCompatibilityApprovals.ApprovedProfile> approvals,
            ObjectNode environment, String generation, String gameVersion, ClassLoader actualLoader,
            Runnable currentHost, Runnable initialControl) {
        this(contracts, approvals, environment, generation, gameVersion, actualLoader, currentHost, initialControl,
                NativeCompatibilityMetadataResolver::actualMod);
    }

    NativeCompatibilityMetadataResolver(ContractJson contracts, List<NativeCompatibilityApprovals.ApprovedProfile> approvals,
            ObjectNode environment, String generation, String gameVersion, ClassLoader actualLoader,
            Runnable currentHost, Runnable initialControl, ModLookup mods) {
        if (contracts == null || approvals == null || approvals.size() > 128 || environment == null || generation == null
                || currentHost == null || initialControl == null || mods == null) throw failure("PROFILE_UNAPPROVED");
        this.environment = environment.deepCopy(); this.generation = generation; this.gameVersion = gameVersion;
        this.actualLoader = actualLoader; this.currentHost = currentHost; this.mods = mods;
        int bytes = 0;
        for (var approval : approvals) {
            initialControl.run(); currentHost.run();
            if (approval == null) throw failure("PROFILE_UNAPPROVED");
            byte[] raw = approval.rawProfile();
            bytes = Math.addExact(bytes, raw.length);
            if (raw.length == 0 || raw.length > CompatibilityInterfaceProbe.MAX_PROFILE_BYTES || bytes > 256 * 1024) throw failure("INPUT_LIMIT");
            ObjectNode profile = ContractJson.object(ContractJson.parse(raw)); contracts.validate("CompatibilityProfile", profile);
            if (!approval.profileDigest().equals(ContractJson.digest(profile))) throw failure("PROFILE_UNAPPROVED");
            String modId = profile.path("match").path("modId").asText();
            if (modId.isEmpty() || profiles.putIfAbsent(approval.approvedProfileRef(), new Profile(approval, modId)) != null) throw failure("PROFILE_UNAPPROVED");
            initialControl.run(); currentHost.run();
        }
    }

    /** The original request control is retained only for this synchronous scope and is always removed. */
    <T> T inScope(Runnable control, Supplier<T> action) {
        if (closed || active != null || control == null || action == null) throw failure("COMPATIBILITY_SOURCE_UNAVAILABLE");
        Scope scope = new Scope(control); active = scope;
        try {
            T value = null; RuntimeException failure = null;
            try { checkpoint(); value = action.get(); }
            catch (RuntimeException original) { failure = original; }
            try {
                checkCurrentSources();
                for (Use use : scope.used.values()) verifyUse(use);
                checkpoint();
            } catch (RuntimeException current) {
                if (failure == null) failure = current; else if (current != failure) failure.addSuppressed(current);
            }
            if (failure != null) throw failure;
            return value;
        } finally { active = null; }
    }

    void checkApproval(NativeCompatibilityApprovals.ApprovedProfile approval, ObjectNode actualEnvironment, String actualGeneration) {
        checkpoint(); requireProfile(approval);
        if (!environment.equals(actualEnvironment) || !generation.equals(actualGeneration)) throw failure("TARGET_DRIFT");
        checkpoint();
    }

    @Override public NativeCompatibilityApprovals.ResolvedMetadataTarget resolve(NativeCompatibilityApprovals.ApprovedProfile approval) {
        checkpoint(); Profile profile = requireProfile(approval);
        if (active.sourcesChecked) throw failure("REGISTRATION_CLOSED");
        if (actualLoader == null) return null;
        ModIdentity mod = mods.find(profile.modId(), this::checkpoint); checkpoint();
        ModIdentity previous = resolvedMods.get(approval.approvedProfileRef());
        if (previous != null && !previous.equals(mod)) throw failure("SOURCE_CHANGED");
        if (mod == null || !profile.modId().equals(mod.modId()) || mod.version() == null || mod.version().isEmpty() || mod.version().length() > 128) return null;
        Path path; BasicFileAttributes identity;
        try {
            path = ordinaryJar(mod.jar());
            if (path == null) { if (previous != null) throw failure("SOURCE_CHANGED"); return null; }
            identity = attributes(path);
        }
        catch (ContractException failure) {
            if (snapshots.containsKey(mod.jar())) throw failure;
            throw unavailable(failure);
        }
        if (identity == null || identity.size() <= 0 || identity.size() > AdapterLimits.JAR_BYTES) {
            if (previous != null) throw failure("SOURCE_CHANGED"); return null;
        }
        Snapshot snapshot = snapshots.get(path);
        if (snapshot == null) {
            try {
                if (snapshots.size() >= 128) throw failure("SOURCE_LIMIT");
                reserve(identity.size()); checkpoint();
                ApprovedArtifact artifact = ApprovedArtifact.openMetadata(path.getParent(), path, digest -> {
                    checkpoint(); requireProfile(approval);
                    if (!approval.artifactDigest().equals(digest)) throw failure("SOURCE_CHANGED");
                    checkpoint();
                }, this::checkpoint, identity.size());
                checkpoint(); BasicFileAttributes after = attributes(path);
                if (!same(identity, after)) throw failure("SOURCE_CHANGED");
                long charge = artifact.retainedSnapshotBytes();
                if (charge <= 0 || charge > MAX_SNAPSHOT_BYTES - retainedBytes) throw failure("SOURCE_LIMIT");
                snapshot = new Snapshot(path, identity, artifact); retainedBytes += charge; snapshots.put(path, snapshot);
            } catch (ContractException failure) { throw unavailable(failure); }
            active.used.put(path, new Use(snapshot));
        } else {
            if (!approval.artifactDigest().equals(snapshot.artifact().sha256()) || !same(identity, snapshot.identity())) throw failure("SOURCE_CHANGED");
            use(snapshot);
        }
        Use use = active.used.get(path); use.mods.put(approval.approvedProfileRef(), mod);
        resolvedMods.putIfAbsent(approval.approvedProfileRef(), mod);
        PublicJavaAdapter.RuntimeTarget target = new PublicJavaAdapter.RuntimeTarget("fabric", mod.modId(), mod.version(), gameVersion, "server");
        Snapshot selected = snapshot;
        CompatibilityInterfaceProbe.MetadataApproval metadata = new CompatibilityInterfaceProbe.MetadataApproval() {
            @Override public void checkpoint() { NativeCompatibilityMetadataResolver.this.checkpoint(); }
            @Override public void checkProfile(ObjectNode observedProfile, String digest, String artifactDigest, PublicJavaAdapter.RuntimeTarget actualTarget) {
                checkProfilePins(profile, digest, artifactDigest);
                if (!approval.profileDigest().equals(ContractJson.digest(observedProfile)) || !target.equals(actualTarget)) throw failure("PROFILE_UNAPPROVED");
                current(profile, mod, selected);
            }
            @Override public void checkInterface(ObjectNode support, ApprovedArtifact.ClassMetadata observed) {
                checkpoint();
                if (observed == null || observed.actualClass().getClassLoader() != actualLoader
                        || !approval.artifactDigest().equals(observed.jarSha256())
                        || !observed.sourceClassDigest().matches("[0-9a-f]{64}")) throw failure("SOURCE_CHANGED");
                current(profile, mod, selected);
            }
            @Override public void checkCurrent(String digest, String artifactDigest, Class<?> actualClass) {
                checkProfilePins(profile, digest, artifactDigest);
                if (actualClass == null || actualClass.getClassLoader() != actualLoader) throw failure("SOURCE_CHANGED");
                current(profile, mod, selected);
            }
        };
        current(profile, mod, selected); checkpoint();
        return new NativeCompatibilityApprovals.ResolvedMetadataTarget(snapshot.artifact(), actualLoader, target, metadata);
    }

    /** All source bytes are checked before the holder starts its actual registry commit. */
    @Override public void checkCurrentSources() {
        checkpoint();
        if (!active.sourcesChecked) {
            for (Use use : active.used.values()) { verifyUse(use); hashCurrent(use.snapshot); verifyUse(use); }
            active.sourcesChecked = true;
        } else for (Use use : active.used.values()) verifyUse(use);
        checkpoint();
    }

    private void checkProfilePins(Profile expected, String digest, String artifactDigest) {
        checkpoint(); requireProfile(expected.approval());
        if (!expected.approval().profileDigest().equals(digest) || !expected.approval().artifactDigest().equals(artifactDigest)) throw failure("PROFILE_UNAPPROVED");
    }
    private Profile requireProfile(NativeCompatibilityApprovals.ApprovedProfile approval) {
        if (approval == null) throw failure("PROFILE_UNAPPROVED");
        Profile expected = profiles.get(approval.approvedProfileRef());
        if (expected == null || !expected.approval().profileDigest().equals(approval.profileDigest())
                || !expected.approval().artifactDigest().equals(approval.artifactDigest())
                || !expected.approval().allowedInterfaceDigest().equals(approval.allowedInterfaceDigest())
                || !Arrays.equals(expected.approval().rawProfile(), approval.rawProfile())) throw failure("PROFILE_UNAPPROVED");
        return expected;
    }
    private void current(Profile profile, ModIdentity mod, Snapshot snapshot) {
        checkpoint(); requireProfile(profile.approval());
        ModIdentity actual = mods.find(profile.modId(), this::checkpoint); checkpoint();
        if (!mod.equals(actual) || !same(snapshot.identity(), attributes(snapshot.path()))) throw failure("SOURCE_CHANGED");
        use(snapshot); checkpoint();
    }
    private void verifyUse(Use use) {
        checkpoint();
        for (var entry : use.mods.entrySet()) {
            Profile profile = profiles.get(entry.getKey());
            if (profile == null || !entry.getValue().equals(mods.find(profile.modId(), this::checkpoint))) throw failure("SOURCE_CHANGED");
            checkpoint();
        }
        if (!same(use.snapshot.identity(), attributes(use.snapshot.path()))) throw failure("SOURCE_CHANGED");
        checkpoint();
    }
    private void use(Snapshot snapshot) {
        if (!active.used.containsKey(snapshot.path())) {
            if (active.sourcesChecked) throw failure("REGISTRATION_CLOSED");
            reserve(snapshot.identity().size()); hashCurrent(snapshot); active.used.put(snapshot.path(), new Use(snapshot));
        }
    }
    private void reserve(long bytes) {
        checkpoint();
        if (bytes <= 0 || bytes > (MAX_SCOPE_READ_BYTES - active.reservedReadBytes) / 2) throw failure("SOURCE_LIMIT");
        active.reservedReadBytes += bytes * 2; checkpoint();
    }
    private void hashCurrent(Snapshot snapshot) {
        checkpoint(); RuntimeException failure = null; String digest = null;
        try {
            if (!same(snapshot.identity(), attributes(snapshot.path()))) throw failure("SOURCE_CHANGED");
            MessageDigest hash = sha256(); long bytes = 0; ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
            checkpoint();
            try (FileChannel channel = FileChannel.open(snapshot.path(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                checkpoint();
                while (bytes < snapshot.identity().size()) {
                    buffer.limit((int) Math.min(buffer.capacity(), snapshot.identity().size() - bytes));
                    checkpoint(); int count = channel.read(buffer); checkpoint();
                    if (count < 0) throw failure("SOURCE_CHANGED");
                    if (count == 0) throw failure("SOURCE_UNAVAILABLE");
                    bytes += count;
                    if (bytes > snapshot.identity().size()) throw failure("SOURCE_CHANGED");
                    buffer.flip(); hash.update(buffer); buffer.clear(); checkpoint();
                }
                if (bytes != snapshot.identity().size()) throw failure("SOURCE_CHANGED");
                checkpoint(); long currentSize = channel.size(); checkpoint();
                if (currentSize != snapshot.identity().size()) throw failure("SOURCE_CHANGED");
            }
            checkpoint(); digest = HexFormat.of().formatHex(hash.digest());
            if (!snapshot.artifact().sha256().equals(digest)) throw failure("SOURCE_CHANGED");
        } catch (IOException exception) { failure = failure("SOURCE_UNAVAILABLE"); }
        catch (RuntimeException original) { failure = original; }
        try { checkpoint(); if (!same(snapshot.identity(), attributes(snapshot.path()))) throw failure("SOURCE_CHANGED"); checkpoint(); }
        catch (RuntimeException current) { if (failure == null) failure = current; else if (current != failure) failure.addSuppressed(current); }
        if (failure != null) throw failure;
    }
    private BasicFileAttributes attributes(Path path) {
        checkpoint();
        try {
            if (ordinaryJar(path) == null) return null;
            BasicFileAttributes value = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); checkpoint();
            return value.isRegularFile() && !value.isSymbolicLink() && !value.isOther() ? value : null;
        } catch (IOException exception) { throw ioFailure(); }
    }
    private Path ordinaryJar(Path path) {
        checkpoint();
        if (path == null || !path.isAbsolute() || !path.getFileSystem().equals(Path.of(".").getFileSystem())
                || !path.equals(path.normalize()) || path.getFileName() == null || !path.getFileName().toString().endsWith(".jar")
                || path.toString().startsWith("\\\\") || path.getNameCount() > 64) return null;
        for (Path component : path) if (secretSelector(component.toString())) return null;
        try {
            Path ancestor = path;
            while (ancestor != null) {
                checkpoint(); BasicFileAttributes value = Files.readAttributes(ancestor, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); checkpoint();
                if (value.isSymbolicLink() || value.isOther() || (ancestor.equals(path) ? !value.isRegularFile() : !value.isDirectory())) return null;
                ancestor = ancestor.getParent();
            }
            checkpoint(); Path real = path.toRealPath(); checkpoint(); return path.equals(real) ? path : null;
        } catch (IOException exception) { throw ioFailure(); }
    }
    static boolean secretSelector(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.equals(".env") || lower.startsWith(".env.") || lower.equals(".ssh") || lower.equals("id_rsa")
                || lower.equals("id_ecdsa") || lower.equals("id_ed25519") || lower.contains("credential")
                || lower.contains("service-account") || lower.contains("service_account") || lower.contains("api-key")
                || lower.contains("api_key") || lower.contains("ssh-key") || lower.endsWith(".pem") || lower.endsWith(".key")
                || lower.endsWith(".p12") || lower.endsWith(".pfx");
    }
    private void checkpoint() {
        if (closed || active == null) throw failure("COMPATIBILITY_SOURCE_UNAVAILABLE");
        active.control.run(); currentHost.run(); active.control.run();
    }
    private static ModIdentity actualMod(String modId, Runnable checkpoint) {
        checkpoint.run(); var container = FabricLoader.getInstance().getModContainer(modId); checkpoint.run();
        if (container.isEmpty()) return null;
        var selected = container.get(); var origin = selected.getOrigin(); checkpoint.run();
        if (origin == null || origin.getKind() != ModOrigin.Kind.PATH) return null;
        var paths = origin.getPaths(); checkpoint.run(); if (paths == null || paths.size() != 1) return null;
        String actualId = selected.getMetadata().getId(); checkpoint.run();
        String version = selected.getMetadata().getVersion().getFriendlyString(); checkpoint.run();
        return modId.equals(actualId) ? new ModIdentity(actualId, version, paths.getFirst()) : null;
    }
    private static boolean same(BasicFileAttributes left, BasicFileAttributes right) {
        return left != null && right != null && left.size() == right.size() && left.lastModifiedTime().equals(right.lastModifiedTime())
                && left.creationTime().equals(right.creationTime()) && Objects.equals(left.fileKey(), right.fileKey());
    }
    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException exception) { throw new AssertionError(exception); }
    }
    private static ContractException unavailable(ContractException original) {
        if (original.getSuppressed().length != 0 || original.code() == null
                || !Set.of("SOURCE_LIMIT", "SOURCE_INVALID", "SOURCE_UNAVAILABLE", "SOURCE_UNAPPROVED").contains(original.code())) return original;
        ContractException wrapped = failure("METADATA_UNAVAILABLE"); wrapped.addSuppressed(original); return wrapped;
    }
    private ContractException ioFailure() {
        ContractException original = failure("SOURCE_UNAVAILABLE");
        try { checkpoint(); } catch (RuntimeException current) { original.addSuppressed(current); }
        return original;
    }
    @Override public void close() { closed = true; active = null; snapshots.clear(); resolvedMods.clear(); profiles.clear(); retainedBytes = 0; }
    private static ContractException failure(String code) { return new ContractException(code, "Actual compatibility input metadata is unavailable, changed or outside its bound"); }
}
