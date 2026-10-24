package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import net.fabricmc.fabric.api.resource.v1.pack.ModPackResources;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.ModOrigin;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.packs.PackResources;
import net.minecraft.server.packs.resources.ResourceManager;

import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Read-only receipts for actual native containers and the current ordered pack view.
 * Archive hashes describe input container bytes, never post-transform class bytes or
 * exhaustive pack contents. No filesystem path or profile-verification decision leaves
 * this collector. Directory, dynamic, opaque and unavailable inputs remain unknown.
 */
final class NativeSourceFacts {
    @FunctionalInterface interface Checkpoint { void check(); }
    private static final int MAX_ENTRIES = 256;
    private static final long MAX_ARCHIVE_BYTES = 128L * 1024 * 1024;
    private static final long MAX_TOTAL_BYTES = 512L * 1024 * 1024;
    private static final int MAX_RESULT_BYTES = 256 * 1024;
    private static final long MAX_OBSERVATION_NANOS = TimeUnit.SECONDS.toNanos(5);
    private static final Pattern MOD_ID = Pattern.compile("[a-z][a-z0-9_-]{0,63}");
    private static final Pattern PUBLIC_ID = Pattern.compile("[A-Za-z0-9_:.+-]{1,128}");
    private static final Pattern PUBLIC_VERSION = Pattern.compile("[A-Za-z0-9 .+()_-]{1,128}");
    private static final Pattern CLASS_NAME = Pattern.compile("[A-Za-z0-9_.$]{1,256}");
    private final long started = System.nanoTime();
    private final ArrayNode archives = ContractJson.newObject().putArray("archives");
    private final Map<Path, CachedArchive> pathReceipts = new HashMap<>();
    private final Map<String, ObjectNode> contentReceipts = new HashMap<>();
    private final Map<String, ObjectNode> modsById = new LinkedHashMap<>();
    private final Checkpoint checkpoint;
    private RuntimeException checkpointFailure;
    private long bytesRead;
    private int entries;

    private record CachedArchive(ObjectNode receipt, BasicFileAttributes attributes) { }

    private NativeSourceFacts(Checkpoint checkpoint) { this.checkpoint = Objects.requireNonNull(checkpoint); }

    static ObjectNode observe(MinecraftServer server, String registryGeneration, ObjectNode environment) {
        return observe(server, registryGeneration, environment, () -> { });
    }

    static ObjectNode observe(MinecraftServer server, String registryGeneration, ObjectNode environment, Checkpoint checkpoint) {
        Objects.requireNonNull(checkpoint).check();
        if (server == null || !server.isSameThread()) {
            throw new ContractException("HOST_NOT_READY", "Native source observation requires the server thread");
        }
        if (registryGeneration == null || !registryGeneration.matches("[0-9]{1,19}")
                || !safeEnvironment(environment)) {
            throw new ContractException("SOURCE_FACTS_INPUT", "Native source observation identity is invalid");
        }
        checkpoint.check();
        return new NativeSourceFacts(checkpoint).collect(server, registryGeneration, environment);
    }

    private ObjectNode collect(MinecraftServer server, String generation, ObjectNode environment) {
        checkDeadline();
        ObjectNode result = ContractJson.newObject().put("format", "mmmm.native.source-facts/1")
                .put("registryGeneration", generation).put("observedAt", Instant.now().toString())
                .put("archiveReceiptScope", "container_input_bytes")
                .put("transformedClassBytes", "not_observed")
                .put("resourceContentEnumeration", "not_performed");
        result.set("environment", environment.deepCopy());
        ObjectNode java = result.putObject("javaRuntime").put("feature", Runtime.version().feature())
                .put("version", Runtime.version().toString());
        putPublic(java, "vendor", System.getProperty("java.vendor"), PUBLIC_VERSION);
        FabricLoader loader = FabricLoader.getInstance();
        result.put("developmentEnvironment", loader.isDevelopmentEnvironment());
        var containers = new ArrayList<ModContainer>();
        for (ModContainer container : loader.getAllMods()) {
            checkDeadline();
            if (containers.size() >= MAX_ENTRIES) throw limit();
            containers.add(container);
        }
        containers.sort(Comparator.comparing(container -> {
            checkDeadline(); String id = container.getMetadata().getId(); checkDeadline(); return id;
        }));
        checkDeadline();
        ArrayNode mods = result.putArray("mods");
        for (ModContainer container : containers) {
            tick();
            ObjectNode mod = mod(container);
            String id = mod.path("modId").asText(null);
            if (id != null && modsById.putIfAbsent(id, mod) != null) {
                throw new ContractException("SOURCE_FACTS_CONFLICT", "Native source metadata contains duplicate mod identities");
            }
            mods.add(mod);
        }
        ObjectNode game = result.putObject("runtimeGame");
        ObjectNode minecraft = modsById.get("minecraft");
        if (minecraft == null) {
            game.set("modRoots", unknown("GAME_MOD_UNAVAILABLE"));
        } else {
            game.set("modRoots", minecraft.path("runtimeRoots").deepCopy());
        }
        game.set("serverClassCodeSource", codeSource(MinecraftServer.class));
        result.set("originalInputGameJars", inputGameJars(loader));
        result.set("platformReadAccess", NativePlatformReadFacts.observe(server, codeSource(NativePlatformReadFacts.class)));
        checkDeadline();
        ArrayNode packs = result.putArray("serverPacks");
        var manager = server.getResourceManager();
        List<PackResources> actualPacks = new ArrayList<>();
        // The stream's observed order is retained, including hidden native packs.
        // Closing the stream does not close the manager-owned PackResources elements.
        try (var stream = manager.listPacks()) {
            var iterator = stream.iterator();
            int ordinal = 0;
            while (true) {
                checkDeadline(); boolean next = iterator.hasNext(); checkDeadline();
                if (!next) break;
                tick();
                PackResources actual = iterator.next();
                actualPacks.add(actual);
                ObjectNode pack = pack(actual, ordinal++);
                // 최소 unknown envelope의 공간부터 확보한다. 더 큰 graph는 기존 결과 상한 안에서만 교체한다.
                pack.set("privatePackFacts", NativePackFacts.unknown("PACK_IMPLEMENTATION_UNSUPPORTED"));
                packs.add(pack);
                checkDeadline();
            }
        }
        checkDeadline();
        result.putNull("clientPacks");
        result.put("clientPackObservation", "not_observed");
        revalidateArchives();
        result.set("archives", archives);
        result.put("bytesRead", bytesRead).put("entryCount", MAX_ENTRIES);
        checkDeadline();
        int encodedBytes = ContractJson.bytes(result).length;
        checkDeadline();
        if (encodedBytes > MAX_RESULT_BYTES) throw limit();
        List<NativePackFacts.Observation> packObservations = new ArrayList<>();
        checkPackView(server, manager, actualPacks);
        for (int i = 0; i < actualPacks.size(); i++) {
            checkDeadline();
            ObjectNode pack = (ObjectNode) packs.get(i);
            int previous = ContractJson.bytes(pack.get("privatePackFacts")).length;
            checkDeadline();
            NativePackFacts.Observation observed = NativePackFacts.observe(actualPacks.get(i), this::checkDeadline,
                    this::packRoot, MAX_ENTRIES - entries, MAX_RESULT_BYTES - encodedBytes + previous);
            entries += observed.entries();
            packObservations.add(observed);
            checkDeadline(); int current = ContractJson.bytes(observed.facts()).length; checkDeadline();
            encodedBytes += current - previous;
            if (encodedBytes > MAX_RESULT_BYTES) throw limit();
            pack.set("privatePackFacts", observed.facts());
        }
        checkPackView(server, manager, actualPacks);
        for (NativePackFacts.Observation observation : packObservations) { checkDeadline(); observation.revalidate().run(); }
        revalidateArchives();
        result.put("entryCount", entries);
        checkDeadline();
        byte[] encoded = ContractJson.bytes(result);
        checkDeadline();
        if (encoded.length > MAX_RESULT_BYTES) throw limit();
        for (NativePackFacts.Observation observation : packObservations) { checkDeadline(); observation.revalidate().run(); }
        checkPackView(server, manager, actualPacks);
        revalidateArchives();
        checkDeadline();
        return result;
    }

    private void checkPackView(MinecraftServer server, ResourceManager manager, List<PackResources> expected) {
        checkDeadline();
        if (server.getResourceManager() != manager) throw packDrift();
        try (var stream = manager.listPacks()) {
            var iterator = stream.iterator();
            for (PackResources pack : expected) {
                checkDeadline(); boolean next = iterator.hasNext(); checkDeadline();
                if (!next || iterator.next() != pack) throw packDrift();
                checkDeadline();
            }
            checkDeadline(); boolean extra = iterator.hasNext(); checkDeadline();
            if (extra) throw packDrift();
        }
        checkDeadline();
        if (server.getResourceManager() != manager) throw packDrift();
    }

    private static ContractException packDrift() {
        return new ContractException("SOURCE_FACTS_DRIFT", "현재 manager의 실제 pack 객체 또는 순서가 바뀌었습니다");
    }

    private NativePackFacts.RootLink packRoot(Path root) {
        checkDeadline();
        try {
            if (!root.isAbsolute() || !"jar".equalsIgnoreCase(root.getFileSystem().provider().getScheme())) {
                return NativePackFacts.RootLink.unknown("PACK_ROOT_NOT_ZIPFS");
            }
            if (!root.normalize().equals(root)) return NativePackFacts.RootLink.unknown("PACK_ROOT_PREFIX_UNSAFE");
            String absolute = root.toString();
            if (!absolute.startsWith("/")) return NativePackFacts.RootLink.unknown("PACK_ROOT_PREFIX_UNSAFE");
            String prefix = absolute.substring(1);
            if (!safePackPrefix(prefix)) return NativePackFacts.RootLink.unknown("PACK_ROOT_PREFIX_UNSAFE");
            URI uri = root.toUri();
            checkDeadline();
            if (!"jar".equalsIgnoreCase(uri.getScheme())) return NativePackFacts.RootLink.unknown("PACK_ROOT_NOT_ZIPFS");
            // 기존 receipt 조회만 한다. realpath·archive open·hash·member I/O를 추가하지 않는다.
            Path outer = archivePath(uri);
            checkDeadline();
            CachedArchive cached = outer == null ? null : pathReceipts.get(outer);
            if (cached == null) return NativePackFacts.RootLink.unknown("PACK_ROOT_UNMAPPED");
            return new NativePackFacts.RootLink(cached.receipt().path("sourceId").asText(), prefix, null);
        } catch (IOException | IllegalArgumentException | SecurityException failure) {
            checkAfterFailure(failure);
            return NativePackFacts.RootLink.unknown("PACK_ROOT_UNMAPPED");
        } finally { checkDeadline(); }
    }

    private static boolean safePackPrefix(String prefix) {
        if (prefix.length() > 1024 || prefix.getBytes(StandardCharsets.UTF_8).length > 1024 || !Normalizer.isNormalized(prefix, Normalizer.Form.NFC)
                || prefix.indexOf('\\') >= 0 || prefix.indexOf(':') >= 0
                || prefix.indexOf('<') >= 0 || prefix.indexOf('>') >= 0 || prefix.indexOf('"') >= 0
                || prefix.indexOf('|') >= 0 || prefix.indexOf('?') >= 0 || prefix.indexOf('*') >= 0
                || prefix.codePoints().anyMatch(Character::isISOControl)) return false;
        if (prefix.isEmpty()) return true;
        for (String part : prefix.split("/", -1)) {
            String lower = part.toLowerCase(Locale.ROOT);
            String device = lower.split("\\.", 2)[0];
            if (part.isEmpty() || part.equals(".") || part.equals("..") || part.endsWith(".") || part.endsWith(" ")
                    || device.matches("con|prn|aux|nul|com[1-9]|lpt[1-9]")
                    || lower.equals(".env") || lower.startsWith(".env.") || lower.contains("credential")
                    || lower.equals(".ssh") || lower.equals("id_rsa") || lower.equals("id_ecdsa") || lower.equals("id_ed25519")
                    || lower.contains("service-account") || lower.contains("service_account")
                    || lower.contains("api-key") || lower.contains("api_key") || lower.contains("ssh-key")) return false;
        }
        return true;
    }

    private ObjectNode mod(ModContainer container) {
        ObjectNode result = ContractJson.newObject();
        String id = container.getMetadata().getId();
        putPublic(result, "modId", id, MOD_ID);
        result.put("modIdDigest", descriptorDigest(id));
        putPublic(result, "version", container.getMetadata().getVersion().getFriendlyString(), PUBLIC_VERSION);
        ArrayNode roots = result.putArray("runtimeRoots");
        int ordinal = 0;
        for (Path root : container.getRootPaths()) {
            tick();
            ObjectNode receipt = archiveRoot(root);
            receipt.put("rootIndex", ordinal++);
            roots.add(receipt);
        }
        if (roots.isEmpty()) result.put("runtimeRootObservation", "unknown_no_roots");
        else result.put("runtimeRootObservation", "observed_root_list");
        result.set("installation", installation(container));
        return result;
    }

    private ObjectNode installation(ModContainer container) {
        checkDeadline();
        try {
            ModOrigin origin = container.getOrigin();
            checkDeadline();
            if (origin == null) return unknown("INSTALLATION_ORIGIN_UNAVAILABLE");
            ObjectNode result = ContractJson.newObject().put("scope", "installation_origin");
            switch (origin.getKind()) {
                case PATH -> {
                    result.put("kind", "path");
                    ArrayNode paths = result.putArray("archives");
                    int ordinal = 0;
                    for (Path path : origin.getPaths()) {
                        tick();
                        ObjectNode receipt = archiveRoot(path);
                        receipt.put("originIndex", ordinal++);
                        paths.add(receipt);
                    }
                    if (paths.isEmpty()) result.put("status", "unknown");
                    else result.put("status", "observed_origin_list");
                }
                case NESTED -> {
                    result.put("kind", "nested").put("status", "observed_metadata");
                    putPublic(result, "parentModId", origin.getParentModId(), MOD_ID);
                    // A nested archive's original sub-location is separate from runtime roots.
                    result.put("parentSubLocationDigest", descriptorDigest(origin.getParentSubLocation()));
                }
                default -> {
                    result.put("kind", "unknown").put("status", "unknown")
                            .put("reason", "INSTALLATION_ORIGIN_UNAVAILABLE");
                }
            }
            checkDeadline();
            return result;
        } catch (ContractException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            checkAfterFailure(exception);
            return unknown("INSTALLATION_ORIGIN_UNAVAILABLE");
        }
    }

    private ArrayNode inputGameJars(FabricLoader loader) {
        checkDeadline();
        ArrayNode result = ContractJson.newObject().putArray("inputGameJars");
        Object shared = loader.getObjectShare().get("fabric-loader:inputGameJars");
        checkDeadline();
        if (!(shared instanceof List<?> paths) || paths.isEmpty()) {
            result.add(unknown("ORIGINAL_GAME_INPUTS_UNAVAILABLE"));
            return result;
        }
        int ordinal = 0;
        for (Object path : paths) {
            tick();
            ObjectNode receipt = path instanceof Path typed ? archiveRoot(typed) : unknown("ORIGINAL_GAME_INPUT_TYPE");
            receipt.put("inputIndex", ordinal++).put("scope", "original_game_input_container");
            result.add(receipt);
        }
        checkDeadline();
        return result;
    }

    private ObjectNode codeSource(Class<?> type) {
        tick();
        try {
            var domain = type.getProtectionDomain();
            var source = domain == null ? null : domain.getCodeSource();
            URL location = source == null ? null : source.getLocation();
            checkDeadline();
            if (location == null) return unknown("CLASS_CODE_SOURCE_UNAVAILABLE");
            Path path = archivePath(location.toURI());
            if (path == null) return unknown("CLASS_CODE_SOURCE_NOT_ORDINARY_ARCHIVE");
            return archive(path).put("scope", "loaded_class_container");
        } catch (IOException | URISyntaxException | IllegalArgumentException | SecurityException exception) {
            checkAfterFailure(exception);
            return unknown("CLASS_CODE_SOURCE_UNAVAILABLE");
        }
    }

    private ObjectNode pack(PackResources pack, int ordinal) {
        checkDeadline();
        ObjectNode result = ContractJson.newObject().put("packIndex", ordinal)
                .put("resourceContentObservation", "not_enumerated");
        String id = pack.packId();
        putPublic(result, "packId", id, PUBLIC_ID);
        result.put("packIdDigest", descriptorDigest(id));
        String implementation = pack.getClass().getName();
        putPublic(result, "implementationClass", implementation, CLASS_NAME);
        ObjectNode location = result.putObject("location");
        String locationId = pack.location().id();
        putPublic(location, "id", locationId, PUBLIC_ID);
        location.put("idDigest", descriptorDigest(locationId));
        var known = pack.location().knownPackInfo();
        if (known.isPresent()) location.put("knownPackDescriptorDigest", descriptorDigest(known.get().toString()));
        else location.putNull("knownPackDescriptorDigest");
        ObjectNode linked = null;
        if (pack instanceof ModPackResources modPack) {
            String modId = modPack.getFabricModMetadata().getId();
            putPublic(result, "providerModId", modId, MOD_ID);
            linked = modsById.get(modId);
            result.put("linkage", "mod_metadata_to_runtime_roots");
        } else if ("vanilla".equals(id)
                && "net.minecraft.server.packs.VanillaPackResources".equals(implementation)) {
            linked = modsById.get("minecraft");
            result.put("linkage", "vanilla_to_game_runtime_roots");
        } else {
            result.putNull("providerModId").put("linkage", "unknown");
        }
        ArrayNode sources = result.putArray("linkedRuntimeContainerSources");
        if (linked != null) {
            for (var root : linked.path("runtimeRoots")) {
                checkDeadline();
                var source = root.path("sourceId");
                if (source.isTextual()) sources.add(source.asText());
            }
        }
        // A linkage is a container receipt, not proof that arbitrary PackResources
        // implementations serve only those containers. Opaque overlays stay unknown.
        result.put("packSourceCompleteness", "unknown");
        result.put("packSourceReason", linked == null ? "OPAQUE_PACK_RESOURCES" : "CONTENT_MAPPING_NOT_EXHAUSTIVELY_OBSERVED");
        checkDeadline();
        return result;
    }

    private ObjectNode archiveRoot(Path root) {
        checkDeadline();
        if (root == null) return unknown("SOURCE_ROOT_UNAVAILABLE");
        try {
            Path path = archivePath(root.toUri());
            return path == null ? unknown("SOURCE_ROOT_NOT_ORDINARY_ARCHIVE") : archive(path);
        } catch (IOException | IllegalArgumentException | SecurityException exception) {
            checkAfterFailure(exception);
            return unknown("SOURCE_ROOT_UNAVAILABLE");
        }
    }

    private Path archivePath(URI uri) throws IOException {
        checkDeadline();
        if ("file".equalsIgnoreCase(uri.getScheme())) {
            if (uri.getAuthority() != null && !uri.getAuthority().isEmpty()) return null;
            return Path.of(uri);
        }
        if (!"jar".equalsIgnoreCase(uri.getScheme())) return null;
        // This only parses the already-observed ZipFS URI; it does not connect or
        // open another archive. Nested jar:jar: and non-local origins are unknown.
        var connection = uri.toURL().openConnection();
        checkDeadline();
        if (!(connection instanceof JarURLConnection jar)) return null;
        URL underlying = jar.getJarFileURL();
        if (!"file".equalsIgnoreCase(underlying.getProtocol())) return null;
        try {
            URI file = underlying.toURI();
            if (file.getAuthority() != null && !file.getAuthority().isEmpty()) return null;
            return Path.of(file);
        } catch (URISyntaxException exception) {
            return null;
        }
    }

    private ObjectNode archive(Path candidate) {
        checkDeadline();
        ObjectNode receipt = readArchive(candidate);
        // 조기 unknown 반환도 FileChannel close가 끝난 뒤 원 요청을 다시 검사한다.
        checkDeadline();
        return receipt;
    }

    private ObjectNode readArchive(Path candidate) {
        try {
            if (!candidate.isAbsolute() || !candidate.getFileSystem().equals(Path.of(".").getFileSystem())) {
                return unknown("SOURCE_NOT_LOCAL_ARCHIVE");
            }
            Path normalized = candidate.normalize();
            String filename = normalized.getFileName() == null ? "" : normalized.getFileName().toString().toLowerCase(Locale.ROOT);
            if (!allowedArchiveName(filename)) return unknown("SOURCE_NOT_ARCHIVE");
            if (normalized.toString().startsWith("\\\\")) return unknown("SOURCE_NOT_LOCAL_ARCHIVE");
            checkDeadline();
            BasicFileAttributes before = Files.readAttributes(normalized, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            checkDeadline();
            if (!before.isRegularFile() || before.isSymbolicLink() || before.isOther()) return unknown("SOURCE_NOT_ORDINARY_ARCHIVE");
            Path real = normalized.toRealPath();
            checkDeadline();
            if (!real.equals(normalized)) return unknown("SOURCE_LINK_OR_ALIAS");
            CachedArchive cached = pathReceipts.get(real);
            if (cached != null) {
                if (!sameFile(before, cached.attributes())) return unknown("SOURCE_CHANGED_DURING_OBSERVATION");
                return cached.receipt().deepCopy();
            }
            if (before.size() < 4 || before.size() > MAX_ARCHIVE_BYTES) return unknown("SOURCE_ARCHIVE_SIZE_LIMIT");
            if (before.size() > MAX_TOTAL_BYTES - bytesRead) throw limit();
            MessageDigest digest = sha256();
            ByteBuffer buffer = ByteBuffer.allocate(64 * 1024);
            long read = 0;
            boolean archiveHeader = false;
            checkDeadline();
            try (FileChannel channel = FileChannel.open(real, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                checkDeadline();
                long channelSize = channel.size(); checkDeadline();
                if (channelSize != before.size()) return unknown("SOURCE_CHANGED_DURING_OBSERVATION");
                while (true) {
                    checkDeadline();
                    buffer.clear();
                    int count = channel.read(buffer);
                    checkDeadline();
                    if (count < 0) break;
                    if (count == 0) continue;
                    read += count;
                    bytesRead += count;
                    if (read > MAX_ARCHIVE_BYTES || bytesRead > MAX_TOTAL_BYTES || read > before.size()) throw limit();
                    buffer.flip();
                    if (read == count) {
                        if (count < 4) return unknown("SOURCE_ARCHIVE_HEADER_UNAVAILABLE");
                        int a = Byte.toUnsignedInt(buffer.get(0)), b = Byte.toUnsignedInt(buffer.get(1));
                        int c = Byte.toUnsignedInt(buffer.get(2)), d = Byte.toUnsignedInt(buffer.get(3));
                        archiveHeader = a == 0x50 && b == 0x4b
                                && ((c == 3 && d == 4) || (c == 5 && d == 6) || (c == 7 && d == 8));
                        if (!archiveHeader) return unknown("SOURCE_NOT_ZIP_ARCHIVE");
                    }
                    digest.update(buffer);
                    checkDeadline();
                }
                checkDeadline(); channelSize = channel.size(); checkDeadline();
                if (read != before.size() || channelSize != before.size()) return unknown("SOURCE_CHANGED_DURING_OBSERVATION");
            }
            checkDeadline();
            BasicFileAttributes after = Files.readAttributes(real, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            checkDeadline();
            Path currentReal = real.toRealPath(); checkDeadline();
            if (!archiveHeader || !sameFile(before, after) || !real.equals(currentReal)) {
                return unknown("SOURCE_CHANGED_DURING_OBSERVATION");
            }
            String hash = HexFormat.of().formatHex(digest.digest());
            String sourceId = "archive-sha256-" + hash;
            ObjectNode receipt = ContractJson.newObject().put("status", "observed")
                    .put("sourceId", sourceId).put("sha256", hash).put("sizeBytes", read)
                    .put("scope", "container_input_bytes")
                    .put("fileIdentityObservation", before.fileKey() == null ? "unavailable" : "stable_before_after");
            if (!contentReceipts.containsKey(sourceId)) {
                tick();
                ObjectNode source = receipt.deepCopy();
                contentReceipts.put(sourceId, source);
                archives.add(source);
            }
            pathReceipts.put(real, new CachedArchive(receipt, after));
            checkDeadline();
            return receipt.deepCopy();
        } catch (ContractException exception) {
            throw exception;
        } catch (IOException | IllegalArgumentException | SecurityException exception) {
            checkAfterFailure(exception);
            return unknown("SOURCE_ARCHIVE_UNAVAILABLE");
        }
    }

    private static boolean allowedArchiveName(String filename) {
        if (filename.equals(".env") || filename.startsWith(".env.") || filename.contains("credential")
                || filename.contains("service-account") || filename.contains("service_account")
                || filename.contains("api-key") || filename.contains("api_key") || filename.contains("ssh-key")) return false;
        return filename.endsWith(".jar") || filename.endsWith(".zip");
    }

    private static boolean sameFile(BasicFileAttributes before, BasicFileAttributes after) {
        return after.isRegularFile() && !after.isSymbolicLink() && !after.isOther()
                && after.size() == before.size() && after.lastModifiedTime().equals(before.lastModifiedTime())
                && after.creationTime().equals(before.creationTime())
                && Objects.equals(after.fileKey(), before.fileKey());
    }

    private void revalidateArchives() {
        for (var entry : pathReceipts.entrySet()) {
            checkDeadline();
            try {
                BasicFileAttributes current = Files.readAttributes(entry.getKey(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                checkDeadline();
                Path currentReal = entry.getKey().toRealPath(); checkDeadline();
                if (!sameFile(entry.getValue().attributes(), current) || !entry.getKey().equals(currentReal)) {
                    throw new ContractException("SOURCE_FACTS_DRIFT", "Native source containers changed during observation");
                }
            } catch (IOException | SecurityException exception) {
                checkAfterFailure(exception);
                throw new ContractException("SOURCE_FACTS_DRIFT", "Native source containers became unavailable during observation");
            }
        }
        checkDeadline();
    }

    private static boolean safeEnvironment(ObjectNode environment) {
        if (environment == null || environment.size() != 5 || !"game".equals(environment.path("kind").asText())
                || !"server".equals(environment.path("side").asText())) return false;
        for (String key : List.of("gameInstanceId", "sessionEpoch", "worldId")) {
            var value = environment.path(key);
            if (!value.isTextual() || !PUBLIC_ID.matcher(value.asText()).matches()) return false;
        }
        return ContractJson.bytes(environment).length <= 2048;
    }

    private static void putPublic(ObjectNode target, String name, String value, Pattern pattern) {
        if (value != null && pattern.matcher(value).matches()) target.put(name, value);
        else target.putNull(name);
    }

    private static String descriptorDigest(String value) {
        if (value == null || value.length() > 4096) {
            throw new ContractException("SOURCE_FACTS_METADATA", "Native source descriptor exceeds its bound");
        }
        return ContractJson.digest(ContractJson.newObject().put("nativeDescriptor", value));
    }

    private static ObjectNode unknown(String reason) {
        return ContractJson.newObject().put("status", "unknown").put("reason", reason).putNull("sourceId");
    }

    private void tick() {
        checkDeadline();
        if (++entries > MAX_ENTRIES) throw limit();
    }

    private void checkDeadline() {
        // 원 요청의 종료는 이 관측 안에서 되살아나거나 metadata unknown으로 바뀌지 않는다.
        if (checkpointFailure != null) throw checkpointFailure;
        try { checkpoint.check(); }
        catch (RuntimeException failure) { checkpointFailure = failure; throw failure; }
        if (System.nanoTime() - started > MAX_OBSERVATION_NANOS) throw limit();
    }

    private void checkAfterFailure(Throwable failure) {
        try { checkDeadline(); }
        catch (RuntimeException stopped) {
            if (stopped != failure) stopped.addSuppressed(failure);
            throw stopped;
        }
    }

    private static ContractException limit() {
        return new ContractException("SOURCE_OBSERVATION_LIMIT", "Native source observation exceeds its finite limits");
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException exception) { throw new AssertionError(exception); }
    }
}
