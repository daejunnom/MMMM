package io.github.daejunnom.mmmm.javaadapter;

import io.github.daejunnom.mmmm.sdk.ContractException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
}
