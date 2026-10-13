package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.tree.CommandNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.arguments.EntityAnchorArgument;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.phys.Vec2;
import net.minecraft.world.phys.Vec3;
import java.util.ArrayDeque;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;

final class NativeCommands {
    private NativeCommands() { }
    static CommandSourceStack source(ServerPlayer player, ServerLevel level, ObjectNode context) {
        if (!context.has("origin") || !context.has("rotationDegrees") || !context.has("anchor")) {
            throw new ContractException("CONTEXT_INCOMPLETE", "Command source needs origin, rotation and anchor");
        }
        var origin = context.get("origin"); var rotation = context.get("rotationDegrees");
        float pitch = rotation.get(0).floatValue(); float yaw = rotation.get(1).floatValue();
        if (!Float.isFinite(pitch) || !Float.isFinite(yaw)) {
            throw new ContractException("CONTEXT_INVALID", "Native command rotation must remain finite as a Minecraft float");
        }
        return player.createCommandSourceStack().withLevel(level)
                .withPosition(new Vec3(origin.get(0).doubleValue(), origin.get(1).doubleValue(), origin.get(2).doubleValue()))
                .withRotation(new Vec2(pitch, yaw))
                .withAnchor("eyes".equals(context.path("anchor").asText()) ? EntityAnchorArgument.Anchor.EYES : EntityAnchorArgument.Anchor.FEET);
    }
    static void cursor(String text, int offset) {
        if (text.length() > 65_536 || offset < 0 || offset > text.length()
                || offset > 0 && offset < text.length() && Character.isHighSurrogate(text.charAt(offset - 1)) && Character.isLowSurrogate(text.charAt(offset))) {
            throw new ContractException("CURSOR_UTF16_INVALID", "Cursor must be a valid UTF-16 boundary inside the command");
        }
    }
    static CompletionStage<ObjectNode> complete(MinecraftServer server, CommandSourceStack source, ObjectNode context,
                                                String text, int offset) {
        cursor(text, offset);
        var dispatcher = server.getCommands().getDispatcher();
        StringReader reader = new StringReader(text);
        if (text.startsWith("/")) reader.setCursor(1);
        var parsed = dispatcher.parse(reader, source);
        String tree = treeDigest(dispatcher.getRoot(), source);
        return dispatcher.getCompletionSuggestions(parsed, offset).thenApply(suggestions -> {
            ObjectNode result = ContractJson.newObject().put("contextDigest", context.path("contextDigest").asText()).put("commandTreeDigest", tree);
            var values = result.putArray("suggestions");
            for (var suggestion : suggestions.getList()) {
                if (values.size() >= 4096) throw new ContractException("SUGGESTION_LIMIT", "Native suggestion count exceeds its limit");
                cursor(text, suggestion.getRange().getStart()); cursor(text, suggestion.getRange().getEnd());
                values.add(ContractJson.newObject().put("startUtf16", suggestion.getRange().getStart())
                        .put("endUtf16", suggestion.getRange().getEnd()).put("replacement", suggestion.getText())
                        .put("tooltip", suggestion.getTooltip() == null ? "" : suggestion.getTooltip().getString()));
            }
            return result;
        });
    }
    private static String treeDigest(CommandNode<CommandSourceStack> root, CommandSourceStack source) {
        Map<CommandNode<CommandSourceStack>, Integer> ids = new IdentityHashMap<>();
        ArrayDeque<CommandNode<CommandSourceStack>> queue = new ArrayDeque<>();
        ids.put(root, 0); queue.add(root);
        var records = ContractJson.newObject().putArray("nodes");
        while (!queue.isEmpty()) {
            CommandNode<CommandSourceStack> node = queue.removeFirst();
            ObjectNode record = ContractJson.newObject().put("id", ids.get(node)).put("name", node.getName())
                    .put("nativeType", node.getClass().getName()).put("executable", node.getCommand() != null).put("permitted", node.canUse(source));
            var children = record.putArray("children");
            node.getChildren().stream().sorted(java.util.Comparator.comparing(CommandNode::getName)).forEach(child -> {
                if (!ids.containsKey(child)) { ids.put(child, ids.size()); queue.add(child); }
                children.add(ids.get(child));
            });
            CommandNode<CommandSourceStack> redirect = node.getRedirect();
            if (redirect != null) {
                if (!ids.containsKey(redirect)) { ids.put(redirect, ids.size()); queue.add(redirect); }
                record.put("redirect", ids.get(redirect));
            }
            records.add(record);
            if (ids.size() > 100_000) throw new ContractException("COMMAND_TREE_LIMIT", "Native command tree exceeds its limit");
        }
        return ContractJson.digest(records);
    }
}
