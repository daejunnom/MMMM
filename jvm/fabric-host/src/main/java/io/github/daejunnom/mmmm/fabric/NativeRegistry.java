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
    private NativeRegistry() { }
    static ObjectNode observe() {
        ObjectNode result = ContractJson.newObject().put("format", "mmmm.native.registry/1");
        var blocks = result.putArray("blocks");
        var values = new ArrayList<Block>();
        for (Block block : BuiltInRegistries.BLOCK) {
            if (values.size() >= 100_000) throw new ContractException("REGISTRY_LIMIT", "Live block registry exceeds its observation limit");
            values.add(block);
        }
        values.sort(Comparator.comparing(block -> BuiltInRegistries.BLOCK.getKey(block).toString()));
        int propertyCount = 0;
        int enumCount = 0;
        for (Block block : values) {
            ObjectNode record = ContractJson.newObject().put("id", BuiltInRegistries.BLOCK.getKey(block).toString());
            record.set("defaultState", NativeBlocks.state(block.defaultBlockState()));
            ObjectNode properties = record.putObject("properties");
            for (Property<?> property : block.defaultBlockState().getProperties()) {
                if (++propertyCount > 10_000) throw new ContractException("REGISTRY_LIMIT", "Native property observation exceeds its aggregate limit");
                var names = propertyNames(property);
                enumCount += names.size();
                if (enumCount > 40_000) throw new ContractException("REGISTRY_LIMIT", "Native property enums exceed their aggregate limit");
                var possibilities = properties.putArray(property.getName());
                names.stream().sorted().forEach(possibilities::add);
            }
            blocks.add(record);
        }
        var itemIds = new ArrayList<String>();
        for (var item : BuiltInRegistries.ITEM) {
            if (itemIds.size() >= 100_000) throw new ContractException("REGISTRY_LIMIT", "Live item registry exceeds its observation limit");
            itemIds.add(BuiltInRegistries.ITEM.getKey(item).toString());
        }
        var items = result.putArray("items"); itemIds.stream().sorted().forEach(items::add);
        var entityIds = new ArrayList<String>();
        for (var entity : BuiltInRegistries.ENTITY_TYPE) {
            if (entityIds.size() >= 100_000) throw new ContractException("REGISTRY_LIMIT", "Live entity registry exceeds its observation limit");
            entityIds.add(BuiltInRegistries.ENTITY_TYPE.getKey(entity).toString());
        }
        var entities = result.putArray("entityTypes"); entityIds.stream().sorted().forEach(entities::add);
        ContractJson.bytes(result);
        return result;
    }
    private static <T extends Comparable<T>> ArrayList<String> propertyNames(Property<T> property) {
        var values = new ArrayList<String>();
        for (T value : property.getPossibleValues()) {
            if (values.size() >= 4096) throw new ContractException("REGISTRY_LIMIT", "Native property enum exceeds its observation limit");
            values.add(property.getName(value));
        }
        return values;
    }
}
