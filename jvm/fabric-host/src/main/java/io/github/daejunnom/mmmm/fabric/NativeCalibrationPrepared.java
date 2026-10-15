package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.util.Objects;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;

/** Read-only preparation from actual native sources, executables and whole target images.
 * A preparation is neither an Accepted invocation nor a permission or a write profile. */
final class NativeCalibrationPrepared {
    private final MinecraftServer server;
    private final ServerLevel level;
    private final HostSession owner;
    private final NativeCalibrationApproval.Program program;
    private final NativeCalibrationRunner.Pins pins;
    private final String invocationDigest, contextDigest;
    private final Invocation invocation;
    private final NativeCalibrationFunctions.SelectedFunction function;
    private final NativeCalibrationTargetImages.ImagePair images;

    private NativeCalibrationPrepared(MinecraftServer server, ServerLevel level, HostSession owner,
            NativeCalibrationRunner.Pins pins, Invocation invocation, NativeCalibrationApproval.Program program,
            NativeCalibrationFunctions.SelectedFunction function, NativeCalibrationTargetImages.ImagePair images) {
        this.server = server; this.level = level; this.owner = owner; this.pins = pins;
        this.invocation = invocation; this.program = program; this.function = function; this.images = images;
        invocationDigest = ContractJson.digest(invocation.wire()); contextDigest = invocation.contextDigest();
    }
    static NativeCalibrationPrepared observe(MinecraftServer server, ServerLevel level, HostSession owner,
            NativeCalibrationRunner.Pins pins, Invocation original, NativeCalibrationApproval.Program program,
            NativeCalibrationApproval.Control control) {
        Objects.requireNonNull(control);
        return NativeCalibrationFunctions.checked(() -> {
            control.checkpoint();
            var function = NativeCalibrationFunctions.observeSelected(server, program, control);
            var images = NativeCalibrationTargetImages.observe(server, level, owner, original.context(), program, control);
            var prepared = new NativeCalibrationPrepared(server, level, owner, pins, original, program, function, images);
            prepared.checkCurrent(original, program, control); return prepared;
        }, control);
    }
    String invocationDigest() { return invocationDigest; }
    String programDigest() { return program.programDigest(); }
    String contextDigest() { return contextDigest; }
    NativeCalibrationTargetImages.ImagePair images() { return images; }
    NativeCalibrationFunctions.SelectedFunction function() { return function; }

    /** Only before an effect. The exact Program object and original before images cannot be rebound. */
    void checkCurrent(Invocation original, NativeCalibrationApproval.Program actualProgram, NativeCalibrationApproval.Control control) {
        NativeCalibrationFunctions.checked(() -> {
            control.checkpoint();
            if (program != actualProgram || !invocationDigest.equals(ContractJson.digest(original.wire()))
                    || !contextDigest.equals(original.contextDigest()) || !invocation.context().equals(original.context())) throw changed();
            function.checkCurrent(control); function.reobserveSourceBytes(control);
            var current = NativeCalibrationTargetImages.observe(server, level, owner, original.context(), program, control);
            if (!images.objectiveFullTargetKnown() || !images.storageFullTargetKnown()
                    || !current.objectiveFullTargetKnown() || !current.storageFullTargetKnown()
                    || !images.objectiveTargetId().equals(current.objectiveTargetId())
                    || !images.storageTargetId().equals(current.storageTargetId())
                    || !images.objectiveSha256().equals(current.objectiveSha256())
                    || !images.storageSha256().equals(current.storageSha256())) throw changed();
            return null;
        }, control);
    }
    ObjectNode wire(NativeCalibrationApproval.Control control) {
        return NativeCalibrationFunctions.checked(() -> {
            control.checkpoint();
            ObjectNode result = ContractJson.newObject().put("format", "mmmm.native.calibration-ready/1")
                    .put("invocationId", invocation.invocationId()).put("invocationDigest", invocationDigest)
                    .put("programDigest", program.programDigest());
            result.set("targetImages", NativeCalibrationRunFacts.fullImages(pins, invocation.context(), images));
            NativeCalibrationRunFacts.bounded(result); return result;
        }, control);
    }
    private static ContractException changed() { return new ContractException("CALIBRATION_PREPARATION_CHANGED", "The original actual before preparation is no longer current"); }
}
