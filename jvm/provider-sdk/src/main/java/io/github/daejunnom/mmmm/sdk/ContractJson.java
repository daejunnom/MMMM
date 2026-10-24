package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.resource.DisallowSchemaLoader;
import com.networknt.schema.serialization.JsonNodeReader;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;

/** Uses the unchanged repository schema. No DTO-derived schema or network schema loading. */
public final class ContractJson {
    public static final String VERSION = "0.2.0";
    public static final int MAX_BYTES = 8 * 1024 * 1024;
    private static final BigInteger MAX_EXACT_INTEGER = BigInteger.valueOf(9_007_199_254_740_991L);
    private static final String SOURCE_SHA256 = "d731b41cb772ed14c6b341d0199b8714cc7364a2eafd10f0f830c050ea5a3476";
    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(96)
                    .maxStringLength(MAX_BYTES).maxNumberLength(256).build()).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
    private final ObjectNode root;
    private final JsonSchemaFactory factory;
    private final SchemaValidatorsConfig config;
    private final Map<String, JsonSchema> definitions = new HashMap<>();

    public ContractJson() {
        byte[] source;
        try (var stream = ContractJson.class.getResourceAsStream("/mmmm/contracts/mmmm.schema.json")) {
            if (stream == null) throw new ContractException("CONTRACT_MISSING", "Original contract resource is unavailable");
            source = stream.readNBytes(MAX_BYTES + 1);
        } catch (IOException exception) {
            throw new ContractException("CONTRACT_MISSING", "Original contract resource could not be read");
        }
        if (!SOURCE_SHA256.equals(sha256(source))) {
            throw new ContractException("CONTRACT_CHANGED", "Original schema source digest does not match this SDK");
        }
        root = object(parse(source));
        rejectExternalReferences(root);
        config = SchemaValidatorsConfig.builder().formatAssertionsEnabled(true).failFast(true).build();
        factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012, builder -> builder
                .jsonNodeReader(JsonNodeReader.builder().jsonMapper(MAPPER).build())
                .schemaLoaders(loaders -> loaders.add(DisallowSchemaLoader.getInstance())));
    }

    public synchronized void validate(String definition, JsonNode value) {
        if (!root.path("$defs").has(definition)) {
            throw new ContractException("CONTRACT_UNKNOWN", "Unknown contract definition");
        }
        JsonSchema schema = definitions.computeIfAbsent(definition, name -> {
            ObjectNode projected = MAPPER.createObjectNode();
            projected.put("$schema", root.path("$schema").asText());
            projected.set("$defs", root.path("$defs").deepCopy());
            projected.put("$ref", "#/$defs/" + name);
            return factory.getSchema(projected, config);
        });
        validateSchema(schema, value);
    }

    public JsonSchema compileActionSchema(JsonNode schema) {
        if (!schema.isObject() && !schema.isBoolean()) {
            throw new ContractException("ACTION_SCHEMA_INVALID", "An action schema must be an object or boolean");
        }
        checkTree(schema, new int[] {0, 0}, 0);
        JsonNode projected = schema.deepCopy();
        boolean[] canonical = {false};
        localizeOriginalReferences(projected, canonical);
        if (canonical[0]) {
            String namespace = "__mmmm_original_contract";
            ObjectNode object = object(projected);
            if (object.path("$defs").has(namespace) || containsKeyword(object, "$id")) {
                throw new ContractException("ACTION_SCHEMA_INVALID", "Canonical contract references require an unambiguous local schema scope");
            }
            ObjectNode original = newObject(); original.set("$defs", root.path("$defs").deepCopy());
            rebaseOriginalReferences(original, "#/$defs/" + namespace);
            object.withObject("$defs").set(namespace, original);
        }
        rejectExternalReferences(projected);
        try { return factory.getSchema(projected, config); }
        catch (RuntimeException exception) {
            throw new ContractException("ACTION_SCHEMA_INVALID", "The offline action schema could not be compiled");
        }
    }

    /** Exact hash-verified contract URI only; the schema loader still rejects every network request. */
    private void localizeOriginalReferences(JsonNode node, boolean[] used) {
        if (node.isObject()) {
            for (String keyword : new String[] {"$ref", "$dynamicRef", "$recursiveRef"}) {
                if (!node.has(keyword)) continue;
                JsonNode reference = node.get(keyword);
                if (!reference.isTextual()) throw new ContractException("EXTERNAL_SCHEMA_REF", "Schema reference must be text");
                String value = reference.asText(); if (value.startsWith("#")) continue;
                String prefix = root.path("$id").asText() + "#";
                if (!"$ref".equals(keyword) || !value.startsWith(prefix + "/$defs/")) throw new ContractException("EXTERNAL_SCHEMA_REF", "Only the exact original contract URI is available offline");
                String pointer = value.substring(prefix.length()); JsonNode target;
                try { target = root.at(pointer); } catch (IllegalArgumentException exception) { throw new ContractException("EXTERNAL_SCHEMA_REF", "Original contract pointer is invalid"); }
                if (!target.isObject() && !target.isBoolean()) throw new ContractException("EXTERNAL_SCHEMA_REF", "Original contract pointer is unavailable");
                ((ObjectNode) node).put(keyword, "#/$defs/__mmmm_original_contract" + pointer); used[0] = true;
            }
        }
        if (node.isContainerNode()) for (JsonNode child : node) localizeOriginalReferences(child, used);
    }
    private static void rebaseOriginalReferences(JsonNode node, String prefix) {
        if (node.isObject()) for (String keyword : new String[] {"$ref", "$dynamicRef", "$recursiveRef"}) {
            if (node.has(keyword)) ((ObjectNode) node).put(keyword, prefix + node.path(keyword).asText().substring(1));
        }
        if (node.isContainerNode()) for (JsonNode child : node) rebaseOriginalReferences(child, prefix);
    }
    private static boolean containsKeyword(JsonNode node, String keyword) {
        if (node.isObject() && node.has(keyword)) return true;
        if (node.isContainerNode()) for (JsonNode child : node) if (containsKeyword(child, keyword)) return true;
        return false;
    }

    public static void validateSchema(JsonSchema schema, JsonNode value) {
        checkTree(value, new int[] {0, 0}, 0);
        try {
            if (!schema.validate(value).isEmpty()) throw invalid("Value does not match its declared contract");
        } catch (ContractException exception) { throw exception; }
        catch (RuntimeException exception) { throw invalid("Value does not match its declared contract"); }
    }

    public static JsonNode parse(byte[] bytes) {
        if (bytes.length > MAX_BYTES) throw invalid("JSON exceeds the byte limit");
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            JsonNode result = MAPPER.readTree(text);
            if (result == null) throw invalid("Empty JSON is not accepted");
            checkTree(result, new int[] {0, 0}, 0);
            return result;
        } catch (CharacterCodingException exception) { throw invalid("JSON is not valid UTF-8"); }
        catch (IOException exception) { throw invalid("JSON is malformed or contains duplicate keys"); }
    }

    public static ObjectNode object(JsonNode node) {
        if (!(node instanceof ObjectNode object)) throw invalid("A JSON object is required");
        return object;
    }

    public static ObjectNode newObject() { return MAPPER.createObjectNode(); }
    public static byte[] bytes(JsonNode value) {
        checkTree(value, new int[] {0, 0}, 0);
        byte[] result = value.toString().getBytes(StandardCharsets.UTF_8);
        if (result.length > MAX_BYTES) throw invalid("JSON exceeds the byte limit");
        return result;
    }

    public static byte[] canonical(JsonNode value) {
        checkTree(value, new int[] {0, 0}, 0);
        try {
            String json = new String(bytes(value), StandardCharsets.UTF_8);
            if (value.isContainerNode()) return new JsonCanonicalizer(json).getEncodedUTF8();
            // The pinned decoder accepts object/array roots. Its primitive serializer is the same
            // inside a singleton array; remove only that array's brackets, keeping exact JCS bytes.
            byte[] singleton = new JsonCanonicalizer("[" + json + "]").getEncodedUTF8();
            if (singleton.length < 2 || singleton[0] != '[' || singleton[singleton.length - 1] != ']') {
                throw invalid("JSON cannot be canonicalized");
            }
            return Arrays.copyOfRange(singleton, 1, singleton.length - 1);
        }
        catch (IOException exception) { throw invalid("JSON cannot be canonicalized"); }
    }

    public static String digest(JsonNode value) { return sha256(canonical(value)); }
    public static String contextDigest(JsonNode value) {
        ObjectNode projection = object(value).deepCopy();
        projection.remove("contextDigest");
        return digest(projection);
    }
    public static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException exception) { throw new AssertionError(exception); }
    }

    private static void checkTree(JsonNode node, int[] count, int depth) {
        if (++count[0] > 100_000 || depth > 96) throw invalid("JSON exceeds the structural limit");
        if (node.isPojo() || node.isBinary() || node.isMissingNode()) throw invalid("Only JSON tree values are accepted");
        addBytes(count, 2);
        if (node.isTextual()) { checkUnicode(node.textValue()); addStringBytes(count, node.textValue()); }
        if (node.isNumber()) {
            if (!Double.isFinite(node.doubleValue())) throw invalid("Non-finite JSON numbers are forbidden");
            if (node.isBigDecimal() && node.decimalValue().precision() > 256) throw invalid("JSON number exceeds its lexical limit");
            if (node.isIntegralNumber() && node.bigIntegerValue().abs().compareTo(MAX_EXACT_INTEGER) > 0) {
                throw invalid("Large integers must use the contract's decimal string representation");
            }
            addBytes(count, node.asText().length());
        }
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> entries = node.fields();
            while (entries.hasNext()) {
                var entry = entries.next();
                checkUnicode(entry.getKey());
                addStringBytes(count, entry.getKey());
                addBytes(count, 2);
                checkTree(entry.getValue(), count, depth + 1);
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) checkTree(child, count, depth + 1);
        }
    }

    private static void addBytes(int[] count, int bytes) {
        if (bytes < 0 || count[1] > MAX_BYTES - bytes) throw invalid("JSON exceeds the byte limit");
        count[1] += bytes;
    }
    private static void addStringBytes(int[] count, String text) {
        addBytes(count, 2);
        for (int index = 0; index < text.length(); index++) {
            char unit = text.charAt(index);
            int bytes;
            if (unit == '"' || unit == '\\') bytes = 2;
            else if (unit < 32) bytes = unit == '\b' || unit == '\t' || unit == '\n' || unit == '\f' || unit == '\r' ? 2 : 6;
            else if (unit < 128) bytes = 1;
            else if (unit < 2048) bytes = 2;
            else if (Character.isHighSurrogate(unit)) { bytes = 4; index++; }
            else bytes = 3;
            addBytes(count, bytes);
        }
    }

    private static void checkUnicode(String text) {
        for (int index = 0; index < text.length(); index++) {
            char unit = text.charAt(index);
            if (Character.isHighSurrogate(unit)) {
                if (++index >= text.length() || !Character.isLowSurrogate(text.charAt(index))) {
                    throw invalid("Lone surrogate is forbidden");
                }
            } else if (Character.isLowSurrogate(unit)) throw invalid("Lone surrogate is forbidden");
        }
    }

    private static void rejectExternalReferences(JsonNode node) {
        checkTree(node, new int[] {0, 0}, 0);
        rejectReferences(node);
    }
    private static void rejectReferences(JsonNode node) {
        if (node.isObject()) {
            for (String keyword : new String[] {"$ref", "$dynamicRef", "$recursiveRef"}) {
                if (node.has(keyword) && (!node.get(keyword).isTextual() || !node.get(keyword).asText().startsWith("#"))) {
                    throw new ContractException("EXTERNAL_SCHEMA_REF", "Only local schema references are allowed");
                }
            }
        }
        if (node.isContainerNode()) for (JsonNode child : node) rejectReferences(child);
    }

    private static ContractException invalid(String message) { return new ContractException("CONTRACT_INVALID", message); }
}
