package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.fabric.mixin.CommandsContextReadAccess;
import io.github.daejunnom.mmmm.fabric.mixin.ScoreboardReadAccess;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import net.minecraft.server.MinecraftServer;

/** Actual read-access installation and bounded own input-resource receipts, never transformed game bytes. */
final class NativePlatformReadFacts {
    private static final int MAX_RESOURCE_BYTES = 128 * 1024;
    private NativePlatformReadFacts() { }

    static ObjectNode observe(MinecraftServer server, ObjectNode hostContainerReceipt) {
        if (server == null || !server.isSameThread()) throw new ContractException("GAME_THREAD_REQUIRED", "Platform read receipts require the native server thread");
        ObjectNode result = ContractJson.newObject().put("format", "mmmm.native.platform-read-access/1")
                .put("loadedDefinitionBytes", "not_observed").put("gameTransformedDefinitionBytes", "not_observed");
        result.putObject("compiledTargetProfile").put("gameVersion", "26.3").put("javaMajor", 25)
                .put("loaderVersion", "0.19.5").put("fabricApiVersion", "0.162.0+26.3");
        result.set("hostContainer", hostContainerReceipt.deepCopy());
        ObjectNode command = result.putObject("commandExecutionContext");
        try {
            boolean active = CommandsContextReadAccess.mmmm$currentExecutionContext().get() != null;
            command.put("status", "observed").put("access", "native_field_getter").put("present", active);
        } catch (LinkageError | AssertionError exception) {
            command.put("status", "unknown").put("reason", "EXACT_NATIVE_READ_ACCESS_UNAVAILABLE").putNull("present");
        }
        ObjectNode score = result.putObject("scoreboardMaps");
        if (server.getScoreboard() instanceof ScoreboardReadAccess) {
            score.put("status", "observed").put("access", "native_accessor_interface_present");
        } else {
            score.put("status", "unknown").put("reason", "EXACT_NATIVE_READ_ACCESS_UNAVAILABLE");
        }
        var inputs = result.putArray("ownInputResources");
        for (String resource : List.of(
                "io/github/daejunnom/mmmm/fabric/mixin/CommandsContextReadAccess.class",
                "io/github/daejunnom/mmmm/fabric/mixin/ScoreboardReadAccess.class",
                "io/github/daejunnom/mmmm/fabric/NativeCommandDispatch.class",
                "mmmm-platform-read.mixins.json")) inputs.add(input(resource));
        return result;
    }

    private static ObjectNode input(String resource) {
        ObjectNode receipt = ContractJson.newObject().put("resource", resource)
                .put("byteScope", "compiled_input_resource_bytes").put("loadedDefinitionBytes", "not_observed")
                .put("containerAssociation", "host_classloader_resource_lookup");
        try (InputStream stream = NativePlatformReadFacts.class.getClassLoader().getResourceAsStream(resource)) {
            if (stream == null) return receipt.put("status", "unknown").put("reason", "OWN_INPUT_RESOURCE_UNAVAILABLE");
            byte[] bytes = stream.readNBytes(MAX_RESOURCE_BYTES + 1);
            if (bytes.length == 0 || bytes.length > MAX_RESOURCE_BYTES) return receipt.put("status", "unknown").put("reason", "OWN_INPUT_RESOURCE_LIMIT");
            MessageDigest sha;
            try { sha = MessageDigest.getInstance("SHA-256"); }
            catch (NoSuchAlgorithmException exception) { throw new AssertionError(exception); }
            return receipt.put("status", "observed").put("sha256", HexFormat.of().formatHex(sha.digest(bytes)))
                    .put("sizeBytes", bytes.length);
        } catch (IOException | SecurityException exception) {
            return receipt.put("status", "unknown").put("reason", "OWN_INPUT_RESOURCE_UNAVAILABLE");
        }
    }
}
