package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The original handoff digests are independent expectations for Java's JCS
 * implementation and the Rust consumer of the same inputs. No new fixture
 * snapshot is needed: the original project already has nested revisions.
 */
final class DigestProjectionTest {
    @TestFactory
    Stream<DynamicTest> everyOriginalFixtureMatchesItsDeclaredProjection() throws IOException {
        ObjectNode projections = readObject("contracts/digest-projections.json");
        return records().map(record -> DynamicTest.dynamicTest(requiredText(record, "file"), () -> {
            String definition = requiredText(record, "type");
            String field = requiredText(record, "field");
            String expected = requiredText(record, "digest");
            ObjectNode example = readExample(record);
            ObjectNode unchanged = example.deepCopy();

            assertTrue(excludedFields(projections, definition).contains(field),
                    "The fixture's self-digest must be excluded by the original projection");
            assertEquals(expected, requiredText(example, field),
                    "The original fixture index and embedded self-digest must agree");
            assertEquals(expected, projectedDigest(projections, definition, example),
                    "Java canonicalization must match the original independently fixed digest");
            if ("ExecutionContext".equals(definition)) {
                assertEquals(expected, ContractJson.contextDigest(example),
                        "The SDK context projection must agree with the original projection");
            }
            assertEquals(unchanged, example, "Digest calculation must preserve its input");
        }));
    }

    @TestFactory
    Stream<DynamicTest> excludedTopLevelFieldsDoNotChangeOriginalDigests() throws IOException {
        ObjectNode projections = readObject("contracts/digest-projections.json");
        return records().map(record -> DynamicTest.dynamicTest(requiredText(record, "file"), () -> {
            String definition = requiredText(record, "type");
            String expected = requiredText(record, "digest");
            ObjectNode example = readExample(record);
            ObjectNode unchanged = example.deepCopy();

            for (String field : excludedFields(projections, definition)) {
                ObjectNode changed = example.deepCopy();
                String replacement = "0".repeat(64);
                if (replacement.equals(requiredText(example, field))) replacement = "1".repeat(64);
                changed.put(field, replacement);

                assertEquals(expected, projectedDigest(projections, definition, changed), field);
                assertNotEquals(ContractJson.digest(example), ContractJson.digest(changed),
                        "The fixture mutation must actually change the full JSON digest");
                if ("ExecutionContext".equals(definition)) {
                    assertEquals(expected, ContractJson.contextDigest(changed));
                }
            }
            assertEquals(unchanged, example, "Exclusion checks must preserve the original fixture");
        }));
    }

    @Test
    void anOriginalNestedRevisionRemainsPartOfTheProjectDigest() throws IOException {
        ObjectNode projections = readObject("contracts/digest-projections.json");
        JsonNode record;
        try (Stream<JsonNode> originalRecords = records()) {
            record = originalRecords.filter(value -> "Project".equals(requiredText(value, "type")))
                    .findFirst().orElseThrow(() -> new AssertionError("Original Project digest fixture is missing"));
        }
        ObjectNode example = readExample(record);
        ObjectNode unchanged = example.deepCopy();
        ObjectNode changed = example.deepCopy();
        JsonNode ownedResources = changed.get("ownedResources");
        assertNotNull(ownedResources, "The original project must carry its owned resource revisions");
        assertTrue(ownedResources.isArray() && !ownedResources.isEmpty());
        ObjectNode resource = ContractJson.object(ownedResources.get(0));
        String originalRevision = requiredText(resource, "revision");
        assertTrue(excludedFields(projections, "Project").contains("revision"));
        resource.put("revision", originalRevision.equals("0".repeat(64)) ? "1".repeat(64) : "0".repeat(64));

        String expected = requiredText(record, "digest");
        assertEquals(expected, projectedDigest(projections, "Project", example));
        assertNotEquals(expected, projectedDigest(projections, "Project", changed),
                "A top-level exclusion must not remove nested owned-resource revisions");
        assertEquals(unchanged, example, "Nested mutation must not modify the original fixture");
    }

    private static Stream<JsonNode> records() throws IOException {
        JsonNode records = readObject("tests/digest-fixtures.json").get("records");
        assertNotNull(records, "The original digest index must contain records");
        assertTrue(records.isArray(), "Digest fixture records must be an array");
        assertFalse(records.isEmpty(), "An empty digest index must not pass without checking examples");
        return StreamSupport.stream(records.spliterator(), false);
    }

    private static ObjectNode readExample(JsonNode record) throws IOException {
        String file = requiredText(record, "file");
        assertTrue(file.matches("[a-z0-9][a-z0-9.-]*\\.json"),
                "The digest index must identify a direct original example JSON file");
        return readObject("examples/" + file);
    }

    private static ObjectNode readObject(String relative) throws IOException {
        String configuredCheckout = System.getProperty("mmmm.checkout");
        assertNotNull(configuredCheckout, "The test task must provide mmmm.checkout");
        assertFalse(configuredCheckout.isBlank(), "mmmm.checkout must name the original fixture checkout");
        Path checkout = Path.of(configuredCheckout).toAbsolutePath().normalize();
        Path path = checkout.resolve(relative).normalize();
        assertTrue(path.startsWith(checkout), "Only files inside the configured checkout may be read");
        try (var input = Files.newInputStream(path)) {
            return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1)));
        }
    }

    private static String projectedDigest(ObjectNode projections, String definition, ObjectNode value) {
        ObjectNode projected = value.deepCopy();
        for (String field : excludedFields(projections, definition)) projected.remove(field);
        return ContractJson.digest(projected);
    }

    private static List<String> excludedFields(ObjectNode projections, String definition) {
        assertEquals(ContractJson.VERSION, requiredText(projections, "contractVersion"));
        assertEquals("RFC8785+SHA256", requiredText(projections, "algorithm"));
        JsonNode fields = projections.path("excludeTopLevelFields").get(definition);
        assertNotNull(fields, "The original projection must declare " + definition);
        assertTrue(fields.isArray(), "A projection exclusion declaration must be an array");
        List<String> result = new ArrayList<>();
        HashSet<String> seen = new HashSet<>();
        for (JsonNode field : fields) {
            assertTrue(field.isTextual() && !field.textValue().isEmpty());
            assertTrue(seen.add(field.textValue()), "Projection fields must be unique");
            result.add(field.textValue());
        }
        return List.copyOf(result);
    }

    private static String requiredText(JsonNode object, String field) {
        JsonNode value = object.get(field);
        assertNotNull(value, "Missing original fixture field: " + field);
        assertTrue(value.isTextual() && !value.textValue().isEmpty(),
                "Original fixture field must be a non-empty string: " + field);
        return value.textValue();
    }
}
