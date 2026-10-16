package io.github.daejunnom.mmmm.fabric.mixin;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import net.minecraft.resources.Identifier;
import net.minecraft.world.level.saveddata.SavedData;
import net.minecraft.world.level.saveddata.SavedDataType;
import net.minecraft.world.level.storage.SavedDataStorage;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;
import org.spongepowered.asm.mixin.gen.Invoker;

/** Native fields and resolver only; callers must independently prove current absence and scope. */
@Mixin(SavedDataStorage.class)
public interface SavedDataStorageBootstrapAccess {
    @Accessor("cache") Map<SavedDataType<?>, Optional<SavedData>> mmmm$bootstrapCache();
    @Accessor("dataFolder") Path mmmm$bootstrapDataFolder();
    @Invoker("getDataFile") Path mmmm$bootstrapDataFile(Identifier id);
}
