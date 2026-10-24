// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** File-name boundary checks only: these do not claim an actual native bootstrap append. */
final class DefinitionObserverAgentPathTest {
    @TempDir Path directory;

    @Test void unicodeSharedPrefixUsesTheSameJarThroughAnAsciiRelativeName() throws Exception {
        Path shared = Files.createDirectory(directory.resolve("공통"));
        Path working = Files.createDirectory(shared.resolve("scratch"));
        Path cache = Files.createDirectories(shared.resolve("cache/libs"));
        Path selected = jar(cache.resolve("observer.jar"));
        Path relative = DefinitionObserverAgent.bootstrapJarName(selected, working);
        assertFalse(relative.isAbsolute());
        assertTrue(relative.toString().chars().allMatch(character -> character >= 0x20 && character <= 0x7e));
        assertTrue(Files.isSameFile(working.resolve(relative), selected));
        assertEquals(working.relativize(selected), relative);
    }

    @Test void aNonAsciiUnsharedComponentIsRejected() throws Exception {
        Path working = Files.createDirectory(directory.resolve("scratch"));
        Path selected = jar(directory.resolve("관측.jar"));
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(selected, working));
    }

    @Test void aDifferentFileSystemRootCannotSupplyTheNativeName() throws Exception {
        Path working = Files.createDirectory(directory.resolve("scratch"));
        Path archive = directory.resolve("separate-root.zip");
        try (var separate = FileSystems.newFileSystem(URI.create("jar:" + archive.toUri()), Map.of("create", "true"))) {
            assertThrows(IllegalStateException.class,
                    () -> DefinitionObserverAgent.bootstrapJarName(separate.getPath("/observer.jar"), working));
        }
    }

    @Test void emptyFilesAndDirectoriesAreRejected() throws Exception {
        Path working = Files.createDirectory(directory.resolve("scratch"));
        Path empty = Files.createFile(directory.resolve("empty.jar"));
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(empty, working));
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(working, working));
    }

    @Test void relativeInputsAndUnnormalizedTraversalAreRejected() throws Exception {
        Path working = Files.createDirectory(directory.resolve("scratch"));
        Path selected = jar(directory.resolve("observer.jar"));
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(Path.of("observer.jar"), working));
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(selected, Path.of("scratch")));
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(working.resolve("../observer.jar"), working));
    }

    @Test void aNativeNameThatExceedsTheFixedJdkBufferIsRejected() throws Exception {
        Path working = Files.createDirectory(directory.resolve("scratch"));
        Path cache = Files.createDirectories(directory.resolve("a".repeat(100)).resolve("b".repeat(100))
                .resolve("c".repeat(50)));
        Path selected = jar(cache.resolve("observer.jar"));
        assertTrue(working.relativize(selected).toString().length() > 259);
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(selected, working));
    }

    @Test void anOversizedSelectedFileIsRejectedWithoutReadingItsContents() throws Exception {
        Path working = Files.createDirectory(directory.resolve("scratch"));
        Path selected = directory.resolve("oversized.jar");
        try (var file = FileChannel.open(selected, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            file.position(16 * 1024 * 1024);
            file.write(ByteBuffer.wrap(new byte[] {0}));
        }
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(selected, working));
    }

    @Test void aSymbolicLinkToTheSelectedJarIsRejected() throws Exception {
        Path working = Files.createDirectory(directory.resolve("scratch"));
        Path selected = jar(directory.resolve("observer.jar"));
        Path alias = directory.resolve("alias.jar");
        try {
            Files.createSymbolicLink(alias, selected);
        } catch (IOException | UnsupportedOperationException exception) {
            Assumptions.assumeTrue(false, "SYMBOLIC_LINK_CREATION_UNAVAILABLE");
        }
        assertThrows(IllegalStateException.class,
                () -> DefinitionObserverAgent.bootstrapJarName(alias, working));
    }

    private static Path jar(Path path) throws IOException {
        // A bounded empty ZIP is sufficient for path identity. No game/JDK bytecode fixture is copied.
        try (var output = new JarOutputStream(Files.newOutputStream(path, StandardOpenOption.CREATE_NEW))) {
            output.finish();
        }
        return path;
    }
}
