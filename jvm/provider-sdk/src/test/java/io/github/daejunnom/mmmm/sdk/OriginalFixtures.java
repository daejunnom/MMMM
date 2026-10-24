package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** 원본 checkout fixture를 사용하며 테스트용 계약이나 fixture 사본을 만들지 않는다. */
final class OriginalFixtures {
    private OriginalFixtures() { }

    static JsonNode read(String relativePath) throws IOException {
        String checkout = System.getProperty("mmmm.checkout");
        if (checkout == null || checkout.isBlank()) {
            throw new IllegalStateException("The mmmm.checkout property must identify the original contract checkout");
        }
        Path root = Path.of(checkout).toAbsolutePath().normalize();
        Path source = root.resolve(relativePath).normalize();
        if (!source.startsWith(root)) throw new IllegalArgumentException("Fixture path leaves the original checkout");
        try (var input = Files.newInputStream(source)) {
            return ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1));
        }
    }

    static ObjectNode example(String name) throws IOException {
        return ContractJson.object(read("examples/" + name));
    }
}
