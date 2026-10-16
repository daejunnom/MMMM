package io.github.daejunnom.mmmm.fabric.mixin;

import java.util.Map;
import net.minecraft.world.scores.DisplaySlot;
import net.minecraft.world.scores.Objective;
import net.minecraft.world.scores.Scoreboard;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** Exact 26.3 platform views; callers only inspect cardinality, keys and current values. */
@Mixin(Scoreboard.class)
public interface ScoreboardReadAccess {
    @Accessor("playerScores")
    Map<String, ?> mmmm$playerScores();

    @Accessor("displayObjectives")
    Map<DisplaySlot, Objective> mmmm$displayObjectives();
}
