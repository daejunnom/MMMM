package io.github.daejunnom.mmmm.javaadapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Closed scalar/JSON conversions. No POJO serializer, constructor, getter or arbitrary numeric coercion. */
final class JavaValueCodec {
    private static final BigInteger MAX_INTEGER = BigInteger.valueOf(9_007_199_254_740_991L);
    private JavaValueCodec() { }
    static boolean scalar(Class<?> type) {
        return type == String.class || type == boolean.class || type == Boolean.class || type == int.class
                || type == Integer.class || type == float.class || type == Float.class || type == double.class || type == Double.class;
    }
    static boolean valueType(Class<?> type) { return scalar(type) || type == List.class || type == Map.class; }

    static Object argument(JsonNode node, Class<?> type) {
        checkJson(node);
        if (node.isNull()) {
            if (type.isPrimitive()) throw failure("INPUT_INVALID", "Null cannot target a primitive parameter");
            return null;
        }
        if (type == String.class && node.isTextual()) return node.textValue();
        if ((type == boolean.class || type == Boolean.class) && node.isBoolean()) return node.booleanValue();
        if ((type == int.class || type == Integer.class) && node.isIntegralNumber() && node.canConvertToInt()) return node.intValue();
        if ((type == float.class || type == Float.class) && node.isNumber()) {
            float number = node.floatValue();
            if (Float.isFinite(number) && Double.isFinite(node.doubleValue())) return number;
        }
        if ((type == double.class || type == Double.class) && node.isNumber() && Double.isFinite(node.doubleValue())) return node.doubleValue();
        if (type == List.class && node.isArray() || type == Map.class && node.isObject()) return jsonToJava(node, 0, new int[] {0});
        throw failure("INPUT_INVALID", "Value does not match the exact supported Java parameter");
    }

    static ObjectNode result(Object value, String codec) {
        JsonNode converted = javaToJson(value, 0, new int[] {0}, new IdentityHashMap<>());
        ObjectNode data;
        if ("json_compatible".equals(codec) || "completion_stage_json".equals(codec)) {
            data = converted instanceof ObjectNode object ? object : ContractJson.newObject().set("value", converted);
        } else if ("scalar".equals(codec)) data = ContractJson.newObject().set("value", converted);
        else throw failure("UNSUPPORTED_BINDING", "Result codec is not a JSON value codec");
        checkJson(data); return data;
    }

    static void checkJson(JsonNode node) {
        if (node == null) throw failure("INPUT_INVALID", "Mapped JSON is absent");
        checkJsonStructure(node, 0, new int[] {0, 0}, new IdentityHashMap<>());
        if (ContractJson.bytes(node).length > AdapterLimits.JSON_BYTES) {
            throw failure("VALUE_LIMIT", "Mapped JSON exceeds the byte bound");
        }
    }
    private static void checkJsonStructure(JsonNode node, int depth, int[] count, IdentityHashMap<JsonNode, Boolean> path) {
        tick(depth, count);
        if (node.isPojo() || node.isBinary() || node.isMissingNode()) throw failure("INPUT_INVALID", "Only ordinary JSON tree values are supported");
        addBytes(count, 2);
        if (node.isTextual()) addTextBytes(count, node.textValue());
        if (node.isNumber()) {
            if (!Double.isFinite(node.doubleValue()) || node.isIntegralNumber() && node.bigIntegerValue().abs().compareTo(MAX_INTEGER) > 0) {
                throw failure("INPUT_INVALID", "JSON number is outside the exact finite codec boundary");
            }
            addBytes(count, node.asText().length());
        }
        if (node.isContainerNode()) {
            if (path.put(node, Boolean.TRUE) != null) throw failure("INPUT_INVALID", "Mapped JSON contains a cycle");
            try {
                if (node.isObject()) {
                    var fields = node.fields();
                    while (fields.hasNext()) {
                        var entry = fields.next(); addTextBytes(count, entry.getKey()); addBytes(count, 4);
                        checkJsonStructure(entry.getValue(), depth + 1, count, path);
                    }
                } else for (JsonNode child : node) checkJsonStructure(child, depth + 1, count, path);
            }
            finally { path.remove(node); }
        }
    }
    private static void addBytes(int[] count, int bytes) {
        if (bytes < 0 || count[1] > AdapterLimits.JSON_BYTES - bytes) throw failure("VALUE_LIMIT", "JSON exceeds its byte bound before serialization");
        count[1] += bytes;
    }
    private static void addTextBytes(int[] count, String text) {
        addBytes(count, 2);
        for (int index = 0; index < text.length(); index++) {
            char unit = text.charAt(index); int bytes;
            if (unit == '"' || unit == '\\') bytes = 2;
            else if (unit < 32) bytes = unit == '\b' || unit == '\t' || unit == '\n' || unit == '\f' || unit == '\r' ? 2 : 6;
            else if (unit < 128) bytes = 1;
            else if (unit < 2048) bytes = 2;
            else if (Character.isHighSurrogate(unit)) {
                if (++index >= text.length() || !Character.isLowSurrogate(text.charAt(index))) throw failure("INPUT_INVALID", "Lone surrogate is unsupported");
                bytes = 4;
            } else if (Character.isLowSurrogate(unit)) throw failure("INPUT_INVALID", "Lone surrogate is unsupported");
            else bytes = 3;
            addBytes(count, bytes);
        }
    }

    private static Object jsonToJava(JsonNode node, int depth, int[] count) {
        tick(depth, count);
        if (node.isNull()) return null;
        if (node.isTextual()) return node.textValue();
        if (node.isBoolean()) return node.booleanValue();
        if (node.isIntegralNumber()) return node.bigIntegerValue();
        if (node.isNumber()) return node.doubleValue();
        if (node.isArray()) {
            List<Object> list = new ArrayList<>();
            for (JsonNode child : node) list.add(jsonToJava(child, depth + 1, count));
            return java.util.Collections.unmodifiableList(list);
        }
        if (node.isObject()) {
            Map<String, Object> map = new LinkedHashMap<>();
            node.fields().forEachRemaining(entry -> map.put(entry.getKey(), jsonToJava(entry.getValue(), depth + 1, count)));
            return java.util.Collections.unmodifiableMap(map);
        }
        throw failure("INPUT_INVALID", "Only JSON values are accepted");
    }

    private static JsonNode javaToJson(Object value, int depth, int[] count, IdentityHashMap<Object, Boolean> path) {
        tick(depth, count); JsonNodeFactory factory = JsonNodeFactory.instance;
        if (value == null) return factory.nullNode();
        if (value instanceof String text) return factory.textNode(text);
        if (value instanceof Boolean flag) return factory.booleanNode(flag);
        if (value instanceof Integer number) return factory.numberNode(number);
        if (value instanceof Long number) return integer(BigInteger.valueOf(number));
        if (value instanceof BigInteger number) return integer(number);
        if (value instanceof Float number && Float.isFinite(number)) return factory.numberNode(number);
        if (value instanceof Double number && Double.isFinite(number)) return factory.numberNode(number);
        if (value instanceof BigDecimal number && Double.isFinite(number.doubleValue()) && number.precision() <= 256) return factory.numberNode(number);
        if (!(value instanceof List<?>) && !(value instanceof Map<?, ?>)) throw failure("OUTPUT_INVALID", "Return contains an unsupported Java value");
        if (path.put(value, Boolean.TRUE) != null) throw failure("OUTPUT_INVALID", "Return contains a container cycle");
        try {
            if (value instanceof List<?> list) {
                if (list.size() > AdapterLimits.JSON_NODES) throw failure("VALUE_LIMIT", "Return list exceeds the node bound");
                ArrayNode array = factory.arrayNode();
                for (Object child : list) array.add(javaToJson(child, depth + 1, count, path));
                return array;
            }
            Map<?, ?> map = (Map<?, ?>) value;
            if (map.size() > AdapterLimits.JSON_NODES) throw failure("VALUE_LIMIT", "Return map exceeds the node bound");
            ObjectNode object = factory.objectNode();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) throw failure("OUTPUT_INVALID", "Return map keys must be strings");
                object.set(key, javaToJson(entry.getValue(), depth + 1, count, path));
            }
            return object;
        } finally { path.remove(value); }
    }
    private static JsonNode integer(BigInteger number) {
        if (number.abs().compareTo(MAX_INTEGER) > 0) throw failure("OUTPUT_INVALID", "Large integers require an explicit decimal-string codec");
        return JsonNodeFactory.instance.numberNode(number);
    }
    private static void tick(int depth, int[] count) {
        if (depth > AdapterLimits.JSON_DEPTH || ++count[0] > AdapterLimits.JSON_NODES) throw failure("VALUE_LIMIT", "Value exceeds its structural bound");
    }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
}
