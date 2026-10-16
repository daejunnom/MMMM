package io.github.daejunnom.mmmm.javaadapter;

import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Crafted tiny JARs are required to inspect hostile source names; real fixture classes cover invocation separately. */
final class ApprovedArtifactTest {
    @TempDir Path root;
    @Test void traversalAndBinaryNameAliasingAreRejected() throws IOException {
        for (String name : new String[] {"../outside.class", "a.b.class", "a//b.class", "META-INF/versions/25/a/B.class"}) {
            Path jar = root.resolve("invalid-" + Math.abs(name.hashCode()) + ".jar");
            try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
                output.putNextEntry(new JarEntry(name)); output.write(new byte[] {0, 1}); output.closeEntry();
            }
            assertEquals("SOURCE_INVALID", assertThrows(ContractException.class,
                    () -> ApprovedArtifact.open(root, jar, observed -> { })).code());
        }
    }
    @Test void declaredApprovalCannotReplaceActualSourceDigestOrRoot() throws IOException {
        Path jar = root.resolve("empty.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("a/B.class")); output.write(new byte[] {0, 1}); output.closeEntry();
        }
        assertEquals("SOURCE_UNAPPROVED", assertThrows(ContractException.class,
                () -> ApprovedArtifact.open(root, jar, observed -> { throw new ContractException("SOURCE_UNAPPROVED", "Fixture did not approve actual SHA"); })).code());
        assertEquals("SOURCE_UNAPPROVED", assertThrows(ContractException.class,
                () -> ApprovedArtifact.open(root.resolve("another-root"), jar, observed -> { })).code());
    }

    @Test void metadataSourceObservationDoesNotInitializeOrReplaceTheExecutionApproval() throws IOException {
        System.clearProperty("mmmm.javaadapter.fixture.initialized");
        Path jar = root.resolve("metadata.jar"); byte[] definition;
        try (var input = getClass().getResourceAsStream("/org/mmmm/fixture/LegacyApi.class")) {
            assertNotNull(input); definition = input.readAllBytes();
        }
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("org/mmmm/fixture/LegacyApi.class")); output.write(definition); output.closeEntry();
        }
        AtomicInteger checkpoints = new AtomicInteger(); String jarDigest = ContractJson.sha256(Files.readAllBytes(jar));
        ApprovedArtifact artifact = ApprovedArtifact.openMetadata(root, jar, digest -> assertEquals(jarDigest, digest), checkpoints::incrementAndGet);
        ClassLoader loader = artifact.fixtureLoader();
        ApprovedArtifact.ClassMetadata metadata = artifact.observeMetadata("org.mmmm.fixture.LegacyApi", loader, checkpoints::incrementAndGet);
        assertEquals("org.mmmm.fixture.LegacyApi", metadata.actualClass().getName());
        assertEquals(loader, metadata.actualClass().getClassLoader()); assertEquals(jarDigest, metadata.jarSha256());
        assertEquals(ContractJson.sha256(definition), metadata.sourceClassDigest());
        assertTrue(artifact.retainedSnapshotBytes() > definition.length); assertTrue(checkpoints.get() > 4);
        assertEquals(0, ApprovedArtifact.ClassMetadata.class.getConstructors().length);
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
        assertEquals("SOURCE_UNAPPROVED", assertThrows(ContractException.class,
                () -> artifact.observe("org.mmmm.fixture.LegacyApi", loader, (actual, actualLoader, source, bytes) -> {
                    assertSame(metadata.actualClass(), actual);
                    throw new ContractException("SOURCE_UNAPPROVED", "Metadata is not an execution source grant");
                })).code());
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
    }

    @Test void cancellationInsideMetadataArchiveParsingNeverPublishesAPartialSnapshot() throws IOException {
        Path jar = root.resolve("metadata-cancel.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("a/B.class")); output.write(new byte[256 * 1024]); output.closeEntry();
        }
        AtomicBoolean sourceChecked = new AtomicBoolean(); AtomicInteger parsingSteps = new AtomicInteger();
        AtomicReference<ApprovedArtifact> published = new AtomicReference<>();
        assertEquals("CANCELLATION_REQUESTED", assertThrows(ContractException.class,
                () -> published.set(ApprovedArtifact.openMetadata(root, jar, digest -> sourceChecked.set(true), () -> {
                    if (sourceChecked.get() && parsingSteps.incrementAndGet() == 7) {
                        throw new ContractException("CANCELLATION_REQUESTED", "Original metadata request was cancelled");
                    }
                }))).code());
        assertTrue(sourceChecked.get()); assertTrue(parsingSteps.get() >= 7); assertNull(published.get());
    }

    @Test void metadataSnapshotCannotGrowBeyondItsCapturedInputReservation() throws IOException {
        Path jar = root.resolve("metadata-growth.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("a/B.class")); output.write(new byte[] {0, 1}); output.closeEntry();
        }
        AtomicInteger steps = new AtomicInteger(); AtomicBoolean sourceApproved = new AtomicBoolean();
        assertEquals("SOURCE_CHANGED", assertThrows(ContractException.class,
                () -> ApprovedArtifact.openMetadata(root, jar, digest -> sourceApproved.set(true), () -> {
                    if (steps.incrementAndGet() == 3) {
                        try { Files.write(jar, new byte[] {0}, StandardOpenOption.APPEND); }
                        catch (IOException failure) { throw new AssertionError("Fixture append failed", failure); }
                    }
                })).code());
        assertFalse(sourceApproved.get());
    }

    @Test void callerReservationRejectsGrowthBeforeTheMetadataProducerAdoptsANewSize() throws IOException {
        Path jar = root.resolve("metadata-original-reservation.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("a/B.class")); output.write(new byte[] {0, 1}); output.closeEntry();
        }
        long reserved = Files.size(jar);
        Files.write(jar, new byte[] {0}, StandardOpenOption.APPEND);
        AtomicBoolean sourceApproved = new AtomicBoolean(); AtomicReference<ApprovedArtifact> published = new AtomicReference<>();
        assertEquals("SOURCE_CHANGED", assertThrows(ContractException.class,
                () -> published.set(ApprovedArtifact.openMetadata(root, jar, digest -> sourceApproved.set(true), () -> { }, reserved))).code());
        assertFalse(sourceApproved.get()); assertNull(published.get());
    }

    @Test void metadataSourceFailureAndFollowingOriginalCancellationAreBothPreserved() throws IOException {
        Path jar = root.resolve("metadata-source-and-cancel.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("a/B.class")); output.write(new byte[] {0, 1}); output.closeEntry();
        }
        AtomicBoolean sourceFailed = new AtomicBoolean();
        ContractException original = new ContractException("SOURCE_CHANGED", "Observed source did not match its approval");
        ContractException cancelled = new ContractException("CANCELLATION_REQUESTED", "Original metadata request ended");
        ContractException observed = assertThrows(ContractException.class,
                () -> ApprovedArtifact.openMetadata(root, jar, digest -> { sourceFailed.set(true); throw original; }, () -> {
                    if (sourceFailed.get()) throw cancelled;
                }, Files.size(jar)));
        assertSame(original, observed); assertArrayEquals(new Throwable[] {cancelled}, observed.getSuppressed());
    }

    @Test void metadataClassLookupAndLinkageFailuresKeepTheirOriginalCauseAndCancellation() throws IOException {
        System.clearProperty("mmmm.javaadapter.fixture.initialized");
        Path jar = root.resolve("metadata-lookup-failure.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar));
             var input = getClass().getResourceAsStream("/org/mmmm/fixture/LegacyApi.class")) {
            assertNotNull(input); output.putNextEntry(new JarEntry("org/mmmm/fixture/LegacyApi.class")); output.write(input.readAllBytes()); output.closeEntry();
        }
        ApprovedArtifact artifact = ApprovedArtifact.openMetadata(root, jar, digest -> { }, () -> { });
        for (Throwable cause : new Throwable[] {new ClassNotFoundException("Fixture class lookup failed"), new LinkageError("Fixture class linkage failed")}) {
            AtomicBoolean lookupFailed = new AtomicBoolean();
            ContractException cancelled = new ContractException("CANCELLATION_REQUESTED", "Original lookup request ended");
            ClassLoader loader = new ClassLoader(ClassLoader.getPlatformClassLoader()) {
                @Override protected Class<?> findClass(String name) throws ClassNotFoundException {
                    lookupFailed.set(true); if (cause instanceof LinkageError linkage) throw linkage;
                    throw (ClassNotFoundException) cause;
                }
            };
            ContractException observed = assertThrows(ContractException.class,
                    () -> artifact.observeMetadata("org.mmmm.fixture.LegacyApi", loader, () -> { if (lookupFailed.get()) throw cancelled; }));
            assertEquals("INTERFACE_MISMATCH", observed.code());
            assertArrayEquals(new Throwable[] {cause, cancelled}, observed.getSuppressed());
        }
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
    }
}
