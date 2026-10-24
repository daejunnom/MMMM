package io.github.daejunnom.mmmm.javaadapter;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Existing wire DTO tests cannot exercise concrete Java coercion, container cycles or POJO refusal. */
final class JavaValueCodecTest {
    @Test void numericNullAndExactParameterBoundariesRemainClosed() {
        var factory = JsonNodeFactory.instance;
        assertEquals(Integer.MIN_VALUE, JavaValueCodec.argument(factory.numberNode(Integer.MIN_VALUE), int.class));
        assertEquals(Integer.MAX_VALUE, JavaValueCodec.argument(factory.numberNode(Integer.MAX_VALUE), int.class));
        assertThrows(ContractException.class, () -> JavaValueCodec.argument(factory.numberNode(1.5), int.class));
        assertThrows(ContractException.class, () -> JavaValueCodec.argument(factory.numberNode(2147483648L), int.class));
        assertThrows(ContractException.class, () -> JavaValueCodec.argument(factory.numberNode(Double.MAX_VALUE), float.class));
        assertThrows(ContractException.class, () -> JavaValueCodec.argument(factory.nullNode(), boolean.class));
        assertThrows(ContractException.class, () -> JavaValueCodec.argument(factory.textNode("type name"), Thread.class));
        assertEquals(null, JavaValueCodec.argument(factory.nullNode(), String.class));
    }
    @Test void jsonInputCyclesDepthPojoAndHugeTextAreRejectedBeforeSerialization() {
        ObjectNode cyclic = ContractJson.newObject(); cyclic.set("self", cyclic);
        assertThrows(ContractException.class, () -> JavaValueCodec.checkJson(cyclic));
        ObjectNode root = ContractJson.newObject(); ObjectNode child = root;
        for (int index = 0; index <= AdapterLimits.JSON_DEPTH; index++) child = child.putObject("child");
        assertThrows(ContractException.class, () -> JavaValueCodec.checkJson(root));
        assertThrows(ContractException.class, () -> JavaValueCodec.checkJson(JsonNodeFactory.instance.pojoNode(new Object())));
        assertThrows(ContractException.class, () -> JavaValueCodec.checkJson(JsonNodeFactory.instance.textNode("x".repeat(AdapterLimits.JSON_BYTES + 1))));
    }
    @Test void resultContainsOnlyBoundedFiniteJsonAndNoArbitraryGetter() {
        assertEquals("MMMM", JavaValueCodec.result(Map.of("text", "MMMM"), "json_compatible").path("text").asText());
        assertEquals(42, JavaValueCodec.result(42, "scalar").path("value").asInt());
        List<Object> cyclic = new ArrayList<>(); cyclic.add(cyclic);
        assertThrows(ContractException.class, () -> JavaValueCodec.result(cyclic, "json_compatible"));
        Map<Object, Object> key = new HashMap<>(); key.put(42, "unsupported");
        assertThrows(ContractException.class, () -> JavaValueCodec.result(key, "json_compatible"));
        assertThrows(ContractException.class, () -> JavaValueCodec.result(Double.NaN, "scalar"));
        assertThrows(ContractException.class, () -> JavaValueCodec.result(new Object(), "scalar"));
    }
}
