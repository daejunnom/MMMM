// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.fixture.provider;

import io.github.daejunnom.mmmm.sdk.ContractException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/** Own JAR byte declaration. This does not attest transformed or loaded code. */
final class FixtureSourceDigest {
    private static final long MAX_JAR_BYTES = 64L * 1024 * 1024;
    private FixtureSourceDigest() { }
    static String observe(Class<?> actualClass) {
        try {
            var source = actualClass.getProtectionDomain().getCodeSource();
            if (source == null) throw unavailable();
            var uri = source.getLocation().toURI();
            if (!"file".equals(uri.getScheme()) || uri.getAuthority() != null) throw unavailable();
            Path path = Path.of(uri).toAbsolutePath().normalize();
            if (!path.equals(path.toRealPath()) || !path.getFileName().toString().endsWith(".jar")) throw unavailable();
            BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.isRegularFile() || before.size() == 0 || before.size() > MAX_JAR_BYTES) throw unavailable();
            MessageDigest digest = MessageDigest.getInstance("SHA-256"); long bytes = 0;
            try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
                byte[] buffer = new byte[16 * 1024]; int count;
                while ((count = input.read(buffer)) != -1) {
                    bytes += count; if (bytes > MAX_JAR_BYTES) throw unavailable(); digest.update(buffer, 0, count);
                }
            }
            BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (bytes != before.size() || before.size() != after.size() || !after.isRegularFile()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !Objects.equals(before.fileKey(), after.fileKey())) throw unavailable();
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException | URISyntaxException | NoSuchAlgorithmException | SecurityException exception) {
            throw unavailable();
        }
    }
    private static ContractException unavailable() {
        return new ContractException("FIXTURE_SOURCE_UNAVAILABLE", "The exact fixture JAR bytes are unavailable or changed");
    }
}
