package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BinaryNode;
import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.POJONode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 원본의 정상 예시는 별도로 검사하고, 이 클래스는 누락된 실패·자원 경계만 추가한다. */
final class StrictJsonBoundaryTest {
    @ParameterizedTest
    @ValueSource(strings = {
            "", "{\"a\":1,\"a\":2}", "{} []", "{\"n\":NaN}", "{\"n\":Infinity}",
            "{\"n\":9007199254740992}", "{\"n\":-9007199254740992}",
            "{\"s\":\"\\uD800\"}", "{\"s\":\"\\uDC00\"}"
    })
    void ambiguousOrNonInteroperableJsonIsRejected(String input) {
        ContractException failure = assertThrows(ContractException.class,
                () -> ContractJson.parse(input.getBytes(StandardCharsets.UTF_8)));
        assertEquals("CONTRACT_INVALID", failure.code());
    }

    @Test
    void malformedUtf8IsRejectedRatherThanReplaced() {
        byte[] overlongEncoding = {'"', (byte) 0xc0, (byte) 0xaf, '"'};
        byte[] incompleteSequence = {'"', (byte) 0xe2, (byte) 0x82, '"'};
        byte[] encodedSurrogate = {'"', (byte) 0xed, (byte) 0xa0, (byte) 0x80, '"'};
        for (byte[] input : new byte[][] {overlongEncoding, incompleteSequence, encodedSurrogate}) {
            ContractException failure = assertThrows(ContractException.class, () -> ContractJson.parse(input));
            assertEquals("CONTRACT_INVALID", failure.code());
        }
    }

    @Test
    void exactIntegerBoundaryAndSupplementaryUnicodeRemainSupported() {
        JsonNode value = assertDoesNotThrow(() -> ContractJson.parse(
                "{\"negative\":-9007199254740991,\"positive\":9007199254740991,\"text\":\"😀\"}"
                        .getBytes(StandardCharsets.UTF_8)));
        assertEquals(-9_007_199_254_740_991L, value.get("negative").longValue());
        assertEquals(9_007_199_254_740_991L, value.get("positive").longValue());
        assertEquals("😀", value.get("text").textValue());
    }

    @Test
    void canonicalBytesFollowUtf16KeyOrderAndNormalizeNegativeZero() {
        JsonNode value = ContractJson.parse(
                "{\"\uE000\":2,\"😀\":1,\"b\":-0.0,\"a\":\"line\\n\"}".getBytes(StandardCharsets.UTF_8));
        byte[] expected = "{\"a\":\"line\\n\",\"b\":0,\"😀\":1,\"\uE000\":2}"
                .getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expected, ContractJson.canonical(value));
    }

    @Test
    void scalarRootUsesTheSameJcsPrimitiveEncodingAsNestedValues() {
        // The handoff's object fixtures cannot detect the pinned decoder's object/array-only root.
        // These expectations are JSON primitive bytes, including unnormalized supplementary text.
        String[][] examples = {
                {"\"say 😀\"", "\"say 😀\""}, {"\"\\u0061\\n\"", "\"a\\n\""},
                {"25.0", "25"}, {"2.5e1", "25"}, {"-0.0", "0"},
                {"1e30", "1e+30"}, {"true", "true"}, {"false", "false"}, {"null", "null"}
        };
        for (String[] example : examples) {
            JsonNode value = ContractJson.parse(example[0].getBytes(StandardCharsets.UTF_8));
            byte[] expected = example[1].getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(expected, ContractJson.canonical(value), example[0]);
            assertEquals(ContractJson.sha256(expected), ContractJson.digest(value));
        }
    }

    @Test
    void oversizedByteInputAndEscapedObjectValuesHaveFiniteBounds() {
        byte[] oversized = new byte[ContractJson.MAX_BYTES + 1];
        Arrays.fill(oversized, (byte) ' ');
        assertThrows(ContractException.class, () -> ContractJson.parse(oversized));

        // A small Java string expands sixfold as JSON; enforce serialized bytes, not char count.
        ObjectNode escaped = ContractJson.newObject().put("value", String.valueOf((char) 0).repeat(ContractJson.MAX_BYTES / 6 + 1));
        assertThrows(ContractException.class, () -> ContractJson.bytes(escaped));
    }

    @Test
    void aggregateNodeAndNestingLimitsRejectProgrammaticTrees() {
        ArrayNode nodes = ContractJson.newObject().arrayNode();
        for (int index = 0; index < 100_000; index++) nodes.addNull();
        assertThrows(ContractException.class, () -> ContractJson.bytes(nodes));

        ObjectNode nested = ContractJson.newObject();
        ObjectNode cursor = nested;
        for (int depth = 0; depth < 97; depth++) cursor = cursor.putObject("next");
        assertThrows(ContractException.class, () -> ContractJson.bytes(nested));
    }

    @Test
    void platformObjectsAndMutableBinaryNodesCannotEnterAnOpenJsonSchema() {
        ContractJson contracts = new ContractJson();
        var openSchema = contracts.compileActionSchema(BooleanNode.TRUE);
        for (JsonNode nonJson : new JsonNode[] {
                new POJONode(new Object()), BinaryNode.valueOf(new byte[] {1, 2}), MissingNode.getInstance()
        }) {
            ObjectNode data = ContractJson.newObject();
            data.set("value", nonJson);
            assertThrows(ContractException.class, () -> ContractJson.validateSchema(openSchema, data));
            assertThrows(ContractException.class, () -> ContractJson.canonical(data));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"$ref", "$dynamicRef", "$recursiveRef"})
    void actionSchemasCannotLoadExternalReferences(String keyword) {
        ContractJson contracts = new ContractJson();
        ObjectNode schema = ContractJson.newObject().put(keyword, "https://example.invalid/contracts/value.json");
        ContractException failure = assertThrows(ContractException.class, () -> contracts.compileActionSchema(schema));
        assertEquals("EXTERNAL_SCHEMA_REF", failure.code());
    }
}
