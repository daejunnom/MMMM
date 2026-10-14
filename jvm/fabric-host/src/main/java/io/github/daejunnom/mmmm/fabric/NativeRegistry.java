package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.world.level.block.Block;
import net.minecraft.world.level.block.state.properties.Property;
import java.util.ArrayList;
import java.util.Comparator;

/** A bounded observation of live registry values. It is not a resource-pack or target-profile proof. */
final class NativeRegistry {
    enum ClassRole { BLOCK, PROPERTY, PROPERTY_VALUE, ITEM, ENTITY_TYPE }
    interface ClassSink {
        void checkpoint();
        void observe(Class<?> actualClass, ClassRole role);
    }
    private NativeRegistry() { }
    static ObjectNode observe() { return observe(null); }
    static ObjectNode observe(ClassSink sink) {
        ObjectNode result = ContractJson.newObject().put("format", "mmmm.native.registry/1");
        var blocks = result.putArray("blocks");
        var values = new ArrayList<Block>();
        for (Block block : BuiltInRegistries.BLOCK) {
            checkpoint(sink);
            if (values.size() >= 100_000) throw new ContractException("REGISTRY_LIMIT", "Live block registry exceeds its observation limit");
            values.add(block);
        }
        values.sort(Comparator.comparing(block -> BuiltInRegistries.BLOCK.getKey(block).toString()));
        int propertyCount = 0;
        int enumCount = 0;
        for (Block block : values) {
            observe(sink, block, ClassRole.BLOCK);
            ObjectNode record = ContractJson.newObject().put("id", BuiltInRegistries.BLOCK.getKey(block).toString());
            record.set("defaultState", NativeBlocks.state(block.defaultBlockState()));
            ObjectNode properties = record.putObject("properties");
            for (Property<?> property : block.defaultBlockState().getProperties()) {
                observe(sink, property, ClassRole.PROPERTY);
                if (++propertyCount > 10_000) throw new ContractException("REGISTRY_LIMIT", "Native property observation exceeds its aggregate limit");
                var names = propertyNames(property, sink);
                enumCount += names.size();
                if (enumCount > 40_000) throw new ContractException("REGISTRY_LIMIT", "Native property enums exceed their aggregate limit");
                var possibilities = properties.putArray(property.getName());
                names.stream().sorted().forEach(possibilities::add);
            }
            blocks.add(record);
        }
        var itemIds = new ArrayList<String>();
        for (var item : BuiltInRegistries.ITEM) {
            observe(sink, item, ClassRole.ITEM);
            if (itemIds.size() >= 100_000) throw new ContractException("REGISTRY_LIMIT", "Live item registry exceeds its observation limit");
            itemIds.add(BuiltInRegistries.ITEM.getKey(item).toString());
        }
        var items = result.putArray("items"); itemIds.stream().sorted().forEach(items::add);
        var entityIds = new ArrayList<String>();
        for (var entity : BuiltInRegistries.ENTITY_TYPE) {
            observe(sink, entity, ClassRole.ENTITY_TYPE);
            if (entityIds.size() >= 100_000) throw new ContractException("REGISTRY_LIMIT", "Live entity registry exceeds its observation limit");
            entityIds.add(BuiltInRegistries.ENTITY_TYPE.getKey(entity).toString());
        }
        var entities = result.putArray("entityTypes"); entityIds.stream().sorted().forEach(entities::add);
        ContractJson.bytes(result);
        return result;
    }
    private static <T extends Comparable<T>> ArrayList<String> propertyNames(Property<T> property, ClassSink sink) {
        var values = new ArrayList<String>();
        for (T value : property.getPossibleValues()) {
            observe(sink, value, ClassRole.PROPERTY_VALUE);
            if (values.size() >= 4096) throw new ContractException("REGISTRY_LIMIT", "Native property enum exceeds its observation limit");
            values.add(property.getName(value));
        }
        return values;
    }
    private static void checkpoint(ClassSink sink) { if (sink != null) sink.checkpoint(); }
    private static void observe(ClassSink sink, Object actual, ClassRole role) {
        if (sink != null) {
            if (actual == null) throw new ContractException("REGISTRY_VALUE_UNAVAILABLE", "Registry observation contains no actual object");
            sink.observe(actual.getClass(), role);
        }
    }
}
