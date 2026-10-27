package io.github.daejunnom.mmmm.fabric.mixin;

import io.github.daejunnom.mmmm.fabric.NativeCalibrationStageHooks;
import net.minecraft.commands.execution.Frame;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Records an actual frame callback only after the native callback returned. */
@Mixin(Frame.class)
public abstract class CalibrationFrameReturnMixin {
    @Inject(method = "returnSuccess(I)V", at = @At("HEAD"))
    private void mmmm$checkReturn(int returned, CallbackInfo callback) { NativeCalibrationStageHooks.nativeBeforeFrameReturn(this, returned); }
    @Inject(method = "returnFailure()V", at = @At("HEAD"))
    private void mmmm$checkFailure(CallbackInfo callback) { NativeCalibrationStageHooks.nativeBeforeFrameReturn(this, null); }
    @Inject(method = "returnSuccess(I)V", at = @At("RETURN"))
    private void mmmm$observeReturn(int returned, CallbackInfo callback) {
        NativeCalibrationStageHooks.nativeFrameReturned(this, returned);
    }
    @Inject(method = "returnFailure()V", at = @At("RETURN"))
    private void mmmm$observeFailure(CallbackInfo callback) {
        NativeCalibrationStageHooks.nativeFrameReturned(this, null);
    }
}
