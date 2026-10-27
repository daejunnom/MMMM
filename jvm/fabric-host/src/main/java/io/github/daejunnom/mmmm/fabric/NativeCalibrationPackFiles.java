package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.observer.DefinitionOwnedPackFilesBridge;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.level.storage.LevelResource;

/** Platform path issuer only. Rust owns the sealed roster and all physical I/O. */
final class NativeCalibrationPackFiles {
    private NativeCalibrationPackFiles() { }

    /** A bounded snapshot of received private Rust bytes, never Java-generated sources. */
    static final class SealedFiles {
        private final String digest;
        private final byte[] frame;
        private final NativeCalibrationBootstrap.Purpose purpose;
        private SealedFiles(String digest, byte[] frame, NativeCalibrationBootstrap.Purpose purpose) {
            this.digest = digest; this.frame = frame; this.purpose = purpose;
        }
        static SealedFiles fromPrivateRustBundle(ObjectNode source) {
            return fromPrivateRustBundle(source, NativeCalibrationBootstrap.Purpose.NUMERIC47);
        }
        static SealedFiles fromPrivateRustBundle(ObjectNode source, NativeCalibrationBootstrap.Purpose purpose) {
            Objects.requireNonNull(purpose);
            HostDispatcher.exactFields(source, purpose == NativeCalibrationBootstrap.Purpose.NUMERIC47
                    ? Set.of("bundleDigest", "rawResource", "entries")
                    : Set.of("bundleDigest", "rawResource", "entries", "sourceKind"));
            if (purpose == NativeCalibrationBootstrap.Purpose.PACK_CASE
                    && !"pack_case".equals(text(source, "sourceKind"))) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
            String digest = digest(source, "bundleDigest");
            JsonNode entries = source.get("entries");
            if (!(entries instanceof ArrayNode) || entries.size() != purpose.entryCount()) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
            long total = 0; String previous = "";
            try {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                try (DataOutputStream out = new DataOutputStream(bytes)) {
                    if (purpose == NativeCalibrationBootstrap.Purpose.NUMERIC47) out.write("MMMMPK01".getBytes(StandardCharsets.US_ASCII));
                    else { out.write("MMMMPK02".getBytes(StandardCharsets.US_ASCII)); out.writeByte(2); }
                    out.write(HexFormat.of().parseHex(digest)); out.writeShort(purpose.entryCount());
                    for (JsonNode value : entries) {
                        ObjectNode entry = ContractJson.object(value);
                        HostDispatcher.exactFields(entry, Set.of("path", "rawSha256", "byteLength", "rawBytesHex"));
                        String path = text(entry, "path"); String sha = digest(entry, "rawSha256");
                        if (purpose == NativeCalibrationBootstrap.Purpose.PACK_CASE && !Set.of("pack.mcmeta",
                                "data/mmmm_calibration/function/pack/entry.mcfunction",
                                "data/mmmm_calibration/function/pack/dependency.mcfunction").contains(path)) {
                            throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
                        }
                        if (path.length() < 1 || path.length() > 240 || !path.matches("[a-z0-9_./-]+")
                                || path.compareTo(previous) <= 0 || !entry.path("byteLength").isIntegralNumber()
                                || !entry.path("byteLength").canConvertToInt()) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
                        int size = entry.path("byteLength").intValue();
                        if (size < 1 || size > 65536 || (total += size) > 1024 * 1024) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
                        String raw = text(entry, "rawBytesHex");
                        if (raw.length() != size * 2 || !raw.matches("[0-9a-f]+")) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
                        byte[] original = HexFormat.of().parseHex(raw);
                        if (!ContractJson.sha256(original).equals(sha)) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
                        byte[] name = path.getBytes(StandardCharsets.US_ASCII);
                        out.writeShort(name.length); out.write(name); out.writeInt(size); out.write(HexFormat.of().parseHex(sha)); out.write(original);
                        previous = path;
                    }
                }
                byte[] canonical = ContractJson.canonical(entries);
                if (!ContractJson.sha256(canonical).equals(digest)) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
                ObjectNode resource = ContractJson.object(source.get("rawResource"));
                HostDispatcher.exactFields(resource, Set.of("resourceId", "sha256", "mediaType", "sizeBytes"));
                if (!text(resource, "resourceId").matches("[a-z0-9][a-z0-9._:-]{0,127}") || text(resource, "mediaType").isEmpty()
                        || !digest(resource, "sha256").equals(digest) || !resource.path("sizeBytes").isIntegralNumber()
                        || !resource.path("sizeBytes").canConvertToLong() || resource.path("sizeBytes").longValue() != canonical.length) {
                    throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID");
                }
                return new SealedFiles(digest, bytes.toByteArray(), purpose);
            } catch (IOException impossible) { throw new IllegalStateException("In-memory source frame failed", impossible); }
        }
        String bundleDigest() { return digest; }
        String repositoryId() { return "file/" + purpose.basename(); }
    }

    static PreparedFiles prepare(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode context,
                                 SealedFiles sealed, Runnable current) {
        Objects.requireNonNull(sealed);
        return NativeCalibrationStateReader.currentContext(server, level, owner, context, current::run, (actual, checkpoint) -> {
            Path root = actualAbsolute(server.getWorldPath(LevelResource.DATAPACK_DIR));
            PreparedFiles prepared = new PreparedFiles(server, level, owner, actual, sealed, root);
            prepared.checkCurrent(checkpoint::check);
            return prepared;
        });
    }
    static final class PreparedFiles {
        private final MinecraftServer server;
        private final ServerLevel level;
        private final HostSession owner;
        private final ObjectNode context;
        private final SealedFiles sealed;
        private final Path root;
        private boolean attempted;
        private PreparedFiles(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode context, SealedFiles sealed, Path root) {
            this.server = server; this.level = level; this.owner = owner; this.context = context.deepCopy(); this.sealed = sealed; this.root = root;
        }
        void checkCurrent(Runnable current) {
            if (attempted) throw failure("CALIBRATION_PACK_ALREADY_ATTEMPTED");
            NativeCalibrationStateReader.currentContext(server, level, owner, context, current::run, (actual, checkpoint) -> {
                NativeCall port = packCall(this, checkpoint::check);
                DefinitionOwnedPackFilesBridge.observePackAbsence(port, sealed.frame); return null;
            });
        }
        ObjectNode beforeTargets() {
            ObjectNode raw = object(); raw.put("format", "mmmm.native.calibration-bootstrap-absence/1"); raw.put("targetId", sealed.purpose.targetId());
            raw.put("status", "known"); raw.put("presence", "absent"); raw.put("coverage", "full_target");
            raw.put("captureScope", "native_bootstrap_pack_directory_absence");
            ObjectNode selector = raw.putObject("selector"); selector.put("kind", "calibration_pack"); selector.put("sourceBundleDigest", sealed.digest);
            byte[] bytes = ContractJson.canonical(raw);
            ObjectNode target = object(); target.put("targetId", sealed.purpose.targetId()); target.put("rawBytesHex", HexFormat.of().formatHex(bytes));
            target.put("rawSha256", ContractJson.sha256(bytes)); return target;
        }
        FileFacts execute(NativeCalibrationBootstrap.Attempt attempt, Runnable current) {
            Objects.requireNonNull(attempt); Objects.requireNonNull(current);
            attempt.requireActualServer(server);
            Invocation invocation = attempt.original();
            if (attempt.sourceFiles() != sealed) throw failure("CALIBRATION_PACK_INVOCATION_MISMATCH");
            if (attempted || !invocation.context().equals(context) || attempt.purpose() != sealed.purpose
                    || !sealed.purpose.actionId().equals(invocation.actionId())) {
                throw failure("CALIBRATION_PACK_INVOCATION_MISMATCH");
            }
            if (!NativeCalibrationBootstrap.arguments(sealed.purpose, sealed.digest).equals(invocation.arguments())) throw failure("CALIBRATION_PACK_INVOCATION_MISMATCH");
            return NativeCalibrationStateReader.currentContext(server, level, owner, context, current::run, (actual, checkpoint) -> {
                NativeCall port = packCall(this, attempt, checkpoint::check);
                // Sticky before the first CreateNew. Any uncertain partial effect
                // stays preserved and this prepared capability cannot retry.
                if (attempted) throw failure("CALIBRATION_PACK_ALREADY_ATTEMPTED"); attempted = true;
                DefinitionOwnedPackFilesBridge.Receipt receipt = DefinitionOwnedPackFilesBridge.createNew(port, sealed.frame);
                return new FileFacts(root.resolve(sealed.purpose.basename()), sealed.digest, sealed.repositoryId(), receipt);
            });
        }
    }

    /** One fresh read-only JNI frame; the caller must not retain this callback carrier. */
    static Object freshCurrentRootPort(MinecraftServer server, NativeCalibrationBootstrap.Attempt attempt,
                                      Path actualSelectedRoot, Runnable current) {
        Objects.requireNonNull(server); Objects.requireNonNull(attempt); Objects.requireNonNull(current);
        current.run(); attempt.requireActualServer(server);
        var anchor = attempt.heldRootAnchor();
        if (anchor == null) throw failure("CALIBRATION_PACK_ROOT_NOT_HELD");
        Path selected = actualAbsolute(actualSelectedRoot);
        Runnable fresh = () -> {
            current.run(); attempt.requireActualServer(server);
            if (attempt.heldRootAnchor() != anchor) throw failure("CALIBRATION_PACK_ROOT_CHANGED");
            current.run();
        };
        fresh.run();
        // An empty relative path cannot enter the create-new pack operation.
        return new NativeCall(server, attempt, anchor, selected, "", fresh);
    }

    static DefinitionOwnedPackFilesBridge.HeldRootReceipt observeRetainedRoot(MinecraftServer server,
            NativeCalibrationBootstrap.Attempt attempt, Path actualSelectedRoot, Runnable current) {
        Objects.requireNonNull(current); attempt.requireActualServer(server);
        var anchor = attempt.heldRootAnchor();
        if (anchor == null) throw failure("CALIBRATION_PACK_ROOT_NOT_HELD");
        return DefinitionOwnedPackFilesBridge.observeHeldRoot(new NativeCall(server, attempt, anchor,
                actualAbsolute(actualSelectedRoot), "", current));
    }

    static DefinitionOwnedPackFilesBridge.HeldRootReceipt retireRetainedRoot(MinecraftServer server,
            NativeCalibrationBootstrap.Attempt attempt, Runnable cleanup) {
        Objects.requireNonNull(cleanup); attempt.requireActualServer(server);
        var anchor = attempt.rootAnchorForCleanup();
        if (anchor == null) throw failure("CALIBRATION_PACK_ROOT_NOT_HELD");
        // No path is reopened or selected for retirement. Native binding checks
        // precede this fresh cleanup checkpoint and physical release continues
        // even when that checkpoint reports its original failure.
        return DefinitionOwnedPackFilesBridge.retireHeldRoot(new NativeCall(server, attempt, anchor, null, "", cleanup));
    }
    static final class FileFacts {
        private final Path root;
        private final String bundleDigest;
        private final String repositoryId;
        private final DefinitionOwnedPackFilesBridge.Receipt receipt;
        private FileFacts(Path root, String bundleDigest, String repositoryId, DefinitionOwnedPackFilesBridge.Receipt receipt) {
            this.root = root; this.bundleDigest = bundleDigest; this.repositoryId = repositoryId; this.receipt = receipt;
        }
        String repositoryId() { return repositoryId; }
        Path createdPackRoot() { return root; }
        ObjectNode toWire() {
            ObjectNode result = object(); result.put("sourceBundleDigest", bundleDigest); result.put("verifiedFileCount", receipt.files().size());
            ArrayNode entries = result.putArray("files");
            for (DefinitionOwnedPackFilesBridge.FileFact fact : receipt.files()) {
                ObjectNode row = entries.addObject(); row.put("path", fact.path()); row.put("byteLength", fact.byteLength()); row.put("rawSha256", fact.rawSha256());
            }
            return result;
        }
    }

    static AbsentStorage prepareStorageAbsence(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode context,
                                               Path actualDataFolder, Path actualDataFile, Runnable current) {
        return NativeCalibrationStateReader.currentContext(server, level, owner, context, current::run, (actual, checkpoint) -> {
            AbsentStorage result = new AbsentStorage(server, level, owner, actual, actualDataFolder, actualDataFile);
            result.recheck(checkpoint::check); return result;
        });
    }
    /** Only the actual SavedDataStorage accessor/invoker may supply these paths. */
    static final class AbsentStorage {
        private final MinecraftServer server;
        private final ServerLevel level;
        private final HostSession owner;
        private final ObjectNode context;
        private final Path worldRoot;
        private final Path folder;
        private final Path file;
        private final String relative;
        private AbsentStorage(MinecraftServer server, ServerLevel level, HostSession owner, ObjectNode context, Path folder, Path file) {
            this.server = Objects.requireNonNull(server); this.level = Objects.requireNonNull(level); this.owner = Objects.requireNonNull(owner);
            this.context = context.deepCopy(); this.folder = actualAbsolute(folder); this.file = actualAbsolute(file);
            // ROOT is the actual server's fixed world storage anchor. The data
            // directory itself may be absent; never search for another parent.
            this.worldRoot = actualAbsolute(server.getWorldPath(LevelResource.ROOT));
            this.relative = storageRelative(worldRoot, this.folder, this.file);
        }
        void recheck(Runnable current) {
            NativeCalibrationStateReader.currentContext(server, level, owner, context, current::run, (actual, checkpoint) -> {
                Runnable check = () -> {
                    checkpoint.check();
                    if (!actualAbsolute(server.getWorldPath(LevelResource.ROOT)).equals(worldRoot)
                            || !storageRelative(worldRoot, folder, file).equals(relative)) throw failure("CALIBRATION_STORAGE_PATH_CHANGED");
                    checkpoint.check();
                };
                check.run();
                // Existing parents are held by the shared kernel. Only its
                // first actual missing component proves historical absence.
                DefinitionOwnedPackFilesBridge.observeStorageAbsence(new NativeCall(worldRoot, relative, check)); return null;
            });
        }
        ObjectNode facts() {
            ObjectNode result = object(); result.put("format", "mmmm.native.calibration-storage-backing-absence/1"); result.put("presence", "absent"); return result;
        }
    }
    private static NativeCall packCall(PreparedFiles prepared, Runnable current) {
        return new NativeCall(prepared.root, prepared.sealed.purpose.basename(), packCheck(prepared, current));
    }
    private static NativeCall packCall(PreparedFiles prepared, NativeCalibrationBootstrap.Attempt attempt, Runnable current) {
        attempt.requireActualServer(prepared.server);
        if (attempt.sourceFiles() != prepared.sealed) throw failure("CALIBRATION_PACK_INVOCATION_MISMATCH");
        Runnable check = packCheck(prepared, current);
        var anchor = DefinitionOwnedPackFilesBridge.newRootAnchor(prepared.server, attempt, attempt.original(), prepared.sealed);
        // Keep this authority-free locator even if native root registration
        // succeeds but its publication callback or later checkpoint fails.
        attempt.reserveRootAnchor(anchor);
        return new NativeCall(prepared.server, attempt, anchor, prepared.root, prepared.sealed.purpose.basename(), check);
    }
    private static Runnable packCheck(PreparedFiles prepared, Runnable current) {
        Runnable check = () -> {
            current.run();
            if (!actualAbsolute(prepared.server.getWorldPath(LevelResource.DATAPACK_DIR)).equals(prepared.root)) throw failure("CALIBRATION_PACK_ROOT_CHANGED");
            current.run();
        };
        check.run(); return check;
    }
    /** Private, single-call callback carrier. No request callback is retained by a receipt. */
    private static final class NativeCall {
        private final Path root;
        private final String relative;
        private final Runnable current;
        private final MinecraftServer server;
        private final NativeCalibrationBootstrap.Attempt attempt;
        private final DefinitionOwnedPackFilesBridge.RootAnchor anchor;
        private NativeCall(Path root, String relative, Runnable current) {
            this.root = root; this.relative = relative; this.current = current;
            server = null; attempt = null; anchor = null;
        }
        private NativeCall(MinecraftServer server, NativeCalibrationBootstrap.Attempt attempt,
                           DefinitionOwnedPackFilesBridge.RootAnchor anchor, Path root, String relative, Runnable current) {
            this.server = Objects.requireNonNull(server); this.attempt = Objects.requireNonNull(attempt);
            this.anchor = Objects.requireNonNull(anchor); this.root = root; this.relative = relative;
            this.current = Objects.requireNonNull(current); attempt.requireActualServer(server);
        }
        private void checkpoint() { current.run(); }
        private String nativeRoot() { checkpoint(); if (root == null) throw failure("CALIBRATION_PACK_ROOT_NOT_SELECTED"); return root.toString(); }
        private String nativeRelative() { checkpoint(); return relative; }
        // Immutable actual-object/data getters intentionally invoke no request
        // checkpoint. Retirement must verify these bindings before preserving a
        // failed fresh cleanup checkpoint and still attempting physical close.
        private Object nativeServer() { return server; }
        private Object nativeAttempt() { return attempt; }
        private Object nativeInvocation() { return attempt == null ? null : attempt.original(); }
        private Object nativeBundle() { return attempt == null ? null : attempt.sourceFiles(); }
        private Object nativeAnchor() { return anchor; }
        private String nativeInvocationDigest() { return attempt == null ? "" : attempt.invocationDigest(); }
        private String nativeBundleDigest() { return attempt == null ? "" : attempt.sourceBundleDigest(); }
        private String nativeManifestDigest() { return attempt == null ? "" : attempt.frozenManifestDigest(); }
        private void onRootHeld() {
            if (attempt == null || anchor == null) throw failure("CALIBRATION_PACK_ROOT_NOT_HELD");
            attempt.retainRootAnchor(anchor);
        }
        private Object nativeHeldAnchor() { return attempt == null ? null : attempt.heldRootAnchor(); }
    }
    private static ObjectNode object() { return JsonNodeFactory.instance.objectNode(); }
    private static String storageRelative(Path root, Path folder, Path file) {
        if (!folder.startsWith(root) || folder.equals(root) || !file.startsWith(folder) || file.equals(folder)) {
            throw failure("CALIBRATION_STORAGE_PATH_UNSUPPORTED");
        }
        Path relative = root.relativize(file);
        if (relative.isAbsolute() || relative.getNameCount() < 1 || relative.getNameCount() > 64) {
            throw failure("CALIBRATION_STORAGE_PATH_UNSUPPORTED");
        }
        StringBuilder logical = new StringBuilder();
        for (Path component : relative) {
            String name = component.toString();
            if (name.isEmpty() || name.equals(".") || name.equals("..") || name.length() > 255
                    || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf(':') >= 0
                    || name.chars().anyMatch(Character::isISOControl)) throw failure("CALIBRATION_STORAGE_PATH_UNSUPPORTED");
            if (!logical.isEmpty()) logical.append('/'); logical.append(name);
        }
        if (logical.isEmpty() || logical.length() > 4096) throw failure("CALIBRATION_STORAGE_PATH_UNSUPPORTED");
        // This is lexical selection only. Secret/reserved component policy,
        // physical ancestry, links and actual absence remain in the one kernel.
        return logical.toString();
    }
    private static Path actualAbsolute(Path actual) {
        Objects.requireNonNull(actual);
        if (actual.toString().isEmpty()) throw failure("CALIBRATION_STORAGE_PATH_UNSUPPORTED");
        for (Path component : actual) if (component.toString().equals("..")) throw failure("CALIBRATION_STORAGE_PATH_UNSUPPORTED");
        // The game's own paths may start with './'. Remove only that harmless
        // spelling after rejecting every parent traversal. Kernel pins/checks
        // all actual physical ancestors; no caller path or toRealPath is used.
        return actual.toAbsolutePath().normalize();
    }
    private static String text(ObjectNode node, String field) {
        if (!node.path(field).isTextual()) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID"); return node.path(field).textValue();
    }
    private static String digest(ObjectNode node, String field) {
        String value = text(node, field); if (!value.matches("[0-9a-f]{64}")) throw failure("CALIBRATION_SOURCE_BUNDLE_INVALID"); return value;
    }
    private static ContractException failure(String code) { return new ContractException(code, "The actual owned calibration file boundary is unavailable or changed"); }
}
