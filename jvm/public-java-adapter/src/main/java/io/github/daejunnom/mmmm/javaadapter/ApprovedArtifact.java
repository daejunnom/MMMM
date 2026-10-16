package io.github.daejunnom.mmmm.javaadapter;

import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Immutable approved JAR snapshot and observed class bytes, never a description-supplied digest. */
public final class ApprovedArtifact {
    @FunctionalInterface public interface SourceApproval {
        /** Trusted runtime policy checks actual bytes, rights and exact source identity. */
        void check(String observedSha256);
    }
    @FunctionalInterface public interface LoadedClassApproval {
        /** Trusted platform attests this exact loaded Class and ClassLoader, including instrumentation policy. */
        void check(Class<?> actualClass, ClassLoader actualLoader, String jarSha256, String classSha256);
    }
    public record ClassObservation(Class<?> actualClass, String classSha256, String jarSha256) { }
    /** Source-input metadata only. It cannot attest post-transform definitions or authorize execution. */
    public static final class ClassMetadata {
        private final Class<?> actualClass;
        private final String sourceClassDigest;
        private final String jarSha256;
        private ClassMetadata(Class<?> actualClass, String sourceClassDigest, String jarSha256) {
            this.actualClass = actualClass; this.sourceClassDigest = sourceClassDigest; this.jarSha256 = jarSha256;
        }
        public Class<?> actualClass() { return actualClass; }
        /** Digest of the approved JAR's input class bytes; never a loaded, transformed or final definition digest. */
        public String sourceClassDigest() { return sourceClassDigest; }
        public String jarSha256() { return jarSha256; }
    }
    private final Path path;
    private final String sha256;
    private final Map<String, byte[]> classes;
    private ApprovedArtifact(Path path, String sha256, Map<String, byte[]> classes) {
        this.path = path; this.sha256 = sha256; this.classes = classes;
    }

    /** Opens only the exact approved regular JAR. No directory walk, class initialization or loader callback. */
    public static ApprovedArtifact open(Path approvedRoot, Path requestedJar, SourceApproval approval) {
        if (approval == null) throw failure("SOURCE_UNAPPROVED", "Trusted source approval is required");
        try {
            Path root = approvedRoot.toAbsolutePath().normalize();
            Path requested = requestedJar.toAbsolutePath().normalize();
            if (!requested.startsWith(root) || !requested.getFileName().toString().endsWith(".jar")) {
                throw failure("SOURCE_UNAPPROVED", "Artifact is outside its approved source root");
            }
            Path realRoot = root.toRealPath();
            Path real = requested.toRealPath();
            if (!realRoot.equals(root) || !real.equals(requested) || !real.startsWith(realRoot)
                    || !Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS)) {
                throw failure("SOURCE_UNAPPROVED", "Linked or nonregular artifacts are not accepted");
            }
            byte[] bytes;
            try (InputStream input = Files.newInputStream(real, LinkOption.NOFOLLOW_LINKS)) {
                bytes = input.readNBytes(AdapterLimits.JAR_BYTES + 1);
            }
            if (bytes.length > AdapterLimits.JAR_BYTES) throw failure("SOURCE_LIMIT", "Artifact exceeds the byte bound");
            String digest = ContractJson.sha256(bytes);
            approval.check(digest);
            return new ApprovedArtifact(real, digest, readClasses(bytes));
        } catch (IOException exception) { throw failure("SOURCE_UNAVAILABLE", "Approved artifact could not be read"); }
    }

    /** Metadata source collection uses the original cooperative request control throughout bounded I/O. */
    public static ApprovedArtifact openMetadata(Path approvedRoot, Path requestedJar, SourceApproval approval, Runnable checkpoint) {
        return openMetadataSnapshot(approvedRoot, requestedJar, approval, checkpoint, null);
    }

    /** The caller's scoped input reservation must still match before any payload byte is consumed. */
    public static ApprovedArtifact openMetadata(Path approvedRoot, Path requestedJar, SourceApproval approval,
                                                Runnable checkpoint, long expectedSize) {
        return openMetadataSnapshot(approvedRoot, requestedJar, approval, checkpoint, expectedSize);
    }

    private static ApprovedArtifact openMetadataSnapshot(Path approvedRoot, Path requestedJar, SourceApproval approval,
                                                         Runnable checkpoint, Long expectedSize) {
        if (approval == null || checkpoint == null) throw failure("SOURCE_UNAPPROVED", "Trusted source approval and original control are required");
        checkpoint.run();
        try {
            if (expectedSize != null && (expectedSize <= 0 || expectedSize > AdapterLimits.JAR_BYTES)) {
                throw failure("SOURCE_LIMIT", "Caller metadata reservation is outside the source byte bound");
            }
            Path root = approvedRoot.toAbsolutePath().normalize(); Path requested = requestedJar.toAbsolutePath().normalize();
            if (!requested.startsWith(root) || !requested.getFileName().toString().endsWith(".jar")) {
                throw failure("SOURCE_UNAPPROVED", "Metadata artifact is outside its approved source root");
            }
            Path realRoot = root.toRealPath(); Path real = requested.toRealPath(); checkpoint.run();
            if (!realRoot.equals(root) || !real.equals(requested) || !real.startsWith(realRoot)
                    || !Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS)) {
                throw failure("SOURCE_UNAPPROVED", "Linked or nonregular metadata artifacts are not accepted");
            }
            BasicFileAttributes before = Files.readAttributes(real, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            long expectedBytes = before.size();
            if (expectedSize != null && expectedBytes != expectedSize) {
                throw failure("SOURCE_CHANGED", "Metadata artifact size differs from the caller's original input reservation");
            }
            if (!before.isRegularFile() || expectedBytes <= 0 || expectedBytes > AdapterLimits.JAR_BYTES) {
                throw failure("SOURCE_LIMIT", "Metadata artifact size is outside its fixed source bound");
            }
            byte[] bytes;
            try (InputStream input = Files.newInputStream(real, LinkOption.NOFOLLOW_LINKS)) {
                // The regular file's captured size is the input reservation. Growth is checked by
                // attributes below; do not consume an extra byte outside that reserved snapshot.
                bytes = readBounded(input, (int) expectedBytes - 1, checkpoint);
            }
            BasicFileAttributes after = Files.readAttributes(real, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); checkpoint.run();
            if (bytes.length != expectedBytes || !after.isRegularFile() || after.size() != expectedBytes
                    || !before.lastModifiedTime().equals(after.lastModifiedTime()) || !before.creationTime().equals(after.creationTime())
                    || !Objects.equals(before.fileKey(), after.fileKey())) {
                throw failure("SOURCE_CHANGED", "Metadata artifact changed while reading its fixed source snapshot");
            }
            checkpoint.run(); String digest = ContractJson.sha256(bytes); checkpoint.run(); approval.check(digest); checkpoint.run();
            Map<String, byte[]> definitions = readClasses(bytes, checkpoint); checkpoint.run();
            return new ApprovedArtifact(real, digest, definitions);
        } catch (IOException exception) {
            ContractException original = failure("SOURCE_UNAVAILABLE", "Approved metadata artifact could not be read"); original.addSuppressed(exception);
            throw preserveMetadataFailure(original, checkpoint);
        } catch (ContractException original) { throw preserveMetadataFailure(original, checkpoint); }
    }

    public String sha256() { return sha256; }
    /** Conservative install accounting; this is a finite snapshot charge, not a measured JVM heap quota. */
    public long retainedSnapshotBytes() {
        long charge = 512L + 2L * path.toString().length() + 2L * sha256.length();
        for (var entry : classes.entrySet()) charge += 256L + 2L * entry.getKey().length() + ((entry.getValue().length + 7L) & ~7L);
        return charge;
    }

    /** An explicit fixture/tool opt-in: isolated immutable definitions, with platform classes as the parent. */
    public ClassLoader fixtureLoader() {
        return new PinnedLoader(classes, location());
    }

    /**
     * No initialization, method lookup or execution approval. Immutable JAR bytes pin source inputs;
     * transformed class definitions may differ and require the existing separate execution gate.
     */
    public ClassMetadata observeMetadata(String className, ClassLoader loader) {
        return observeMetadata(className, loader, () -> { });
    }

    public ClassMetadata observeMetadata(String className, ClassLoader loader, Runnable checkpoint) {
        if (checkpoint == null) throw failure("SOURCE_UNAPPROVED", "Original metadata control is required");
        checkpoint.run();
        byte[] expected = classes.get(className);
        if (expected == null || loader == null) throw failure("METADATA_UNAVAILABLE", "Class metadata is absent from the approved artifact");
        try {
            Class<?> actual = Class.forName(className, false, loader);
            checkpoint.run();
            if (actual.getClassLoader() != loader) throw failure("CLASSLOADER_MISMATCH", "The actual loader did not define this class");
            CodeSource source = actual.getProtectionDomain().getCodeSource();
            if (source == null || !source.getLocation().toURI().equals(location().toURI())) {
                throw failure("SOURCE_CHANGED", "Metadata class origin differs from the approved artifact");
            }
            // Reuse only the approved source-input snapshot. Reopening class resources here would
            // perform unreserved I/O and still would not attest transformed or final definitions.
            String sourceDigest = ContractJson.sha256(expected);
            checkpoint.run(); return new ClassMetadata(actual, sourceDigest, sha256);
        } catch (ReflectiveOperationException | java.net.URISyntaxException exception) {
            ContractException original = failure("INTERFACE_MISMATCH", "Actual public class metadata is unavailable"); original.addSuppressed(exception);
            throw preserveMetadataFailure(original, checkpoint);
        } catch (LinkageError exception) {
            ContractException original = failure("INTERFACE_MISMATCH", "Class metadata could not be linked without initialization"); original.addSuppressed(exception);
            throw preserveMetadataFailure(original, checkpoint);
        }
    }

    /** Class.forName(false), exact loader identity, origin and bytes precede public member lookup. */
    public ClassObservation observe(String className, ClassLoader loader, LoadedClassApproval approval) {
        byte[] expected = classes.get(className);
        if (expected == null || approval == null || loader == null) throw failure("SOURCE_UNAPPROVED", "Class is absent from the approved artifact");
        try {
            Class<?> actual = Class.forName(className, false, loader);
            if (actual.getClassLoader() != loader) throw failure("CLASSLOADER_MISMATCH", "The approved loader did not define this class");
            CodeSource source = actual.getProtectionDomain().getCodeSource();
            if (source == null || !source.getLocation().toURI().equals(location().toURI())) {
                throw failure("SOURCE_CHANGED", "Loaded class origin differs from the approved artifact");
            }
            byte[] observed;
            if (loader instanceof PinnedLoader pinned && pinned.owns(classes)) {
                observed = pinned.definition(className);
            } else {
                // The trusted platform must additionally reject unobservable transformed definitions.
                try (InputStream input = actual.getResourceAsStream("/" + className.replace('.', '/') + ".class")) {
                    if (input == null) throw failure("SOURCE_UNAVAILABLE", "Loaded class bytes are unavailable");
                    observed = input.readNBytes(AdapterLimits.CLASS_BYTES + 1);
                }
            }
            String classDigest = ContractJson.sha256(observed);
            if (observed.length > AdapterLimits.CLASS_BYTES || !classDigest.equals(ContractJson.sha256(expected))) {
                throw failure("SOURCE_CHANGED", "Loaded class bytes differ from the approved artifact");
            }
            approval.check(actual, loader, sha256, classDigest);
            return new ClassObservation(actual, classDigest, sha256);
        } catch (ReflectiveOperationException | java.net.URISyntaxException | IOException exception) {
            throw failure("INTERFACE_MISMATCH", "Exact public class metadata is unavailable");
        } catch (LinkageError exception) { throw failure("INTERFACE_MISMATCH", "Class metadata could not be linked without initialization"); }
    }

    private URL location() {
        try { return path.toUri().toURL(); }
        catch (java.net.MalformedURLException exception) { throw failure("SOURCE_UNAVAILABLE", "Artifact location is invalid"); }
    }

    private static Map<String, byte[]> readClasses(byte[] jar) throws IOException {
        return readClasses(jar, () -> { });
    }
    private static Map<String, byte[]> readClasses(byte[] jar, Runnable checkpoint) throws IOException {
        Map<String, byte[]> result = new HashMap<>();
        Set<String> names = new HashSet<>(); int entries = 0; int expanded = 0;
        try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(jar))) {
            ZipEntry entry;
            while ((entry = input.getNextEntry()) != null) {
                checkpoint.run();
                String name = entry.getName();
                if (++entries > AdapterLimits.JAR_ENTRIES || name.isEmpty() || name.startsWith("/")
                        || name.contains("\\") || name.indexOf('\0') >= 0 || name.contains(":")) {
                    throw failure("SOURCE_INVALID", "Artifact has an invalid entry or exceeds the entry bound");
                }
                for (String part : name.split("/", -1)) if (part.equals(".") || part.equals("..")) {
                    throw failure("SOURCE_INVALID", "Artifact traversal entries are forbidden");
                }
                String collision = Normalizer.normalize(name, Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
                if (!names.add(collision) || name.startsWith("META-INF/versions/")) {
                    throw failure("SOURCE_INVALID", "Duplicate, colliding or multi-release class selection is unsupported");
                }
                int maximum = name.endsWith(".class") ? AdapterLimits.CLASS_BYTES : AdapterLimits.EXPANDED_BYTES;
                byte[] data = readBounded(input, Math.min(maximum, AdapterLimits.EXPANDED_BYTES - expanded), checkpoint);
                if (data.length > maximum || data.length > AdapterLimits.EXPANDED_BYTES - expanded) {
                    throw failure("SOURCE_LIMIT", "Artifact expanded bytes exceed the bound");
                }
                expanded += data.length;
                if (name.endsWith(".class") && !name.equals("module-info.class")) {
                    String binaryPath = name.substring(0, name.length() - 6);
                    for (String component : binaryPath.split("/", -1)) if (component.isEmpty() || component.contains(".")) {
                        throw failure("SOURCE_INVALID", "Class entry does not use an unambiguous binary name");
                    }
                    String className = name.substring(0, name.length() - 6).replace('/', '.');
                    if (className.startsWith("java.") || className.startsWith("javax.") || result.size() >= AdapterLimits.CLASSES) {
                        throw failure("SOURCE_INVALID", "Artifact class namespace or count is unsupported");
                    }
                    if (result.putIfAbsent(className, data) != null) throw failure("SOURCE_INVALID", "Class binary names collide");
                }
                input.closeEntry();
                checkpoint.run();
            }
        }
        if (result.isEmpty()) throw failure("SOURCE_INVALID", "Artifact contains no class definitions");
        return Map.copyOf(result);
    }

    private static byte[] readBounded(InputStream input, int maximum, Runnable checkpoint) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum + 1, 64 * 1024));
        byte[] buffer = new byte[Math.min(maximum + 1, 64 * 1024)];
        while (output.size() <= maximum) {
            checkpoint.run(); int read = input.read(buffer, 0, Math.min(buffer.length, maximum + 1 - output.size())); checkpoint.run();
            if (read < 0) break;
            if (read == 0) throw new IOException("Metadata stream made no progress");
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static ContractException preserveMetadataFailure(ContractException original, Runnable checkpoint) {
        try { checkpoint.run(); }
        catch (RuntimeException current) { if (current != original) original.addSuppressed(current); }
        return original;
    }

    private static final class PinnedLoader extends ClassLoader {
        private final Map<String, byte[]> definitions;
        private final ProtectionDomain domain;
        private PinnedLoader(Map<String, byte[]> definitions, URL source) {
            super(ClassLoader.getPlatformClassLoader()); this.definitions = definitions;
            domain = new ProtectionDomain(new CodeSource(source, (Certificate[]) null), null, this, null);
        }
        private boolean owns(Map<String, byte[]> value) { return definitions == value; }
        private byte[] definition(String name) { return definitions.get(name); }
        @Override protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] bytes = definitions.get(name);
            if (bytes == null) throw new ClassNotFoundException(name);
            return defineClass(name, bytes, 0, bytes.length, domain);
        }
    }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
}
