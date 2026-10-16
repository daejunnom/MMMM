package io.github.daejunnom.mmmm.fabric.mixin;

import io.github.daejunnom.mmmm.fabric.NativeCalibrationStageHooks;
import java.util.Deque;
import java.util.List;
import net.minecraft.commands.execution.ExecutionContext;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Exact 26.3 readonly queue facts. Empty queues alone cannot hide overflow,
 * which clears both queues; quota exhaustion also returns normally. */
@Mixin(ExecutionContext.class)
public abstract class CalibrationQueueCompletionMixin {
    @Shadow private int commandQuota;
    @Shadow private boolean queueOverflow;
    @Shadow private Deque<?> commandQueue;
    @Shadow private List<?> newTopCommands;

    @Inject(method = "runCommandQueue()V", at = @At("RETURN"))
    private void mmmm$observeActualQueue(CallbackInfo callback) {
        NativeCalibrationStageHooks.nativeQueueReturned(this, commandQuota, queueOverflow, commandQueue.size(), newTopCommands.size());
    }
}
