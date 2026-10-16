package io.github.daejunnom.mmmm.fixture.legacy;

import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.builder.RequiredArgumentBuilder;
import com.mojang.brigadier.context.CommandContext;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.permissions.PermissionLevel;
import java.util.LinkedHashMap;
import java.util.Map;

/** An actual SDK-free game fixture. Commands and the public API use the same bounded session engine. */
public final class LegacyCounterMod implements ModInitializer {
    private final Map<String, LegacyCounterApi.JobTicket> commandTickets = new LinkedHashMap<>();

    @Override public void onInitialize() {
        ServerLifecycleEvents.SERVER_STARTED.register(server -> { commandTickets.clear(); LegacyCounterApi.start(server); });
        ServerTickEvents.END_SERVER_TICK.register(LegacyCounterApi::tick);
        ServerLifecycleEvents.SERVER_STOPPING.register(LegacyCounterApi::stop);
        ServerLifecycleEvents.SERVER_STOPPED.register(server -> { LegacyCounterApi.stop(server); commandTickets.clear(); });
        CommandRegistrationCallback.EVENT.register((dispatcher, registryAccess, selection) -> {
            var root = LiteralArgumentBuilder.<CommandSourceStack>literal("mmmm_fixture");
            root.then(LiteralArgumentBuilder.<CommandSourceStack>literal("read").executes(this::read));
            var write = LiteralArgumentBuilder.<CommandSourceStack>literal("set").requires(LegacyCounterMod::admin);
            var value = RequiredArgumentBuilder.<CommandSourceStack, Integer>argument("value", IntegerArgumentType.integer(0, 10_000))
                    .executes(command -> set(command, "none"))
                    .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("fault", StringArgumentType.word())
                            .executes(command -> set(command, StringArgumentType.getString(command, "fault"))));
            write.then(RequiredArgumentBuilder.<CommandSourceStack, Integer>argument("expected", IntegerArgumentType.integer(0, 10_000)).then(value));
            root.then(write);
            var job = LiteralArgumentBuilder.<CommandSourceStack>literal("job").requires(LegacyCounterMod::admin);
            var delay = RequiredArgumentBuilder.<CommandSourceStack, Integer>argument("delayTicks", IntegerArgumentType.integer(0, 200))
                    .executes(command -> job(command, "none"))
                    .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("fault", StringArgumentType.word())
                            .executes(command -> job(command, StringArgumentType.getString(command, "fault"))));
            job.then(RequiredArgumentBuilder.<CommandSourceStack, Integer>argument("expected", IntegerArgumentType.integer(0, 10_000))
                    .then(RequiredArgumentBuilder.<CommandSourceStack, Integer>argument("value", IntegerArgumentType.integer(0, 10_000)).then(delay)));
            root.then(job);
            root.then(LiteralArgumentBuilder.<CommandSourceStack>literal("cancel").requires(LegacyCounterMod::admin)
                    .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("jobId", StringArgumentType.word()).executes(this::cancel)));
            dispatcher.register(root);
        });
    }

    private int read(CommandContext<CommandSourceStack> command) {
        return execute(command, player -> {
            Map<String, Object> result = LegacyCounterApi.observe(executor(player), dimension(player));
            player.sendSystemMessage(Component.literal("MMMM fixture counter=" + result.get("value") + " revision=" + result.get("revision")
                    + " mutations=" + result.get("mutationCount") + " tick=" + result.get("tick")));
            return (int) result.get("value");
        });
    }

    private int set(CommandContext<CommandSourceStack> command, String fault) {
        return execute(command, player -> {
            int result = LegacyCounterApi.set(executor(player), dimension(player), integer(command, "expected"), integer(command, "value"), fault);
            player.sendSystemMessage(Component.literal("MMMM fixture counter=" + result));
            return result;
        });
    }

    private int job(CommandContext<CommandSourceStack> command, String fault) {
        return execute(command, player -> {
            commandTickets.entrySet().removeIf(entry -> entry.getValue().stage().toCompletableFuture().isDone());
            if (commandTickets.size() >= 16) throw new LegacyCounterException("COUNTER_JOB_LIMIT", "The command ticket limit was reached");
            LegacyCounterApi.JobTicket ticket = LegacyCounterApi.beginJob(executor(player), dimension(player), integer(command, "expected"),
                    integer(command, "value"), integer(command, "delayTicks"), fault);
            commandTickets.put(ticket.id(), ticket);
            player.sendSystemMessage(Component.literal("MMMM fixture job=" + ticket.id() + " status=" + ticket.observe().get("status")
                    + " mutationObserved=" + ticket.observe().get("mutationStarted")));
            var server = player.level().getServer();
            var playerId = player.getUUID();
            ticket.stage().whenComplete((result, failure) -> {
                // All engine completions occur on the original server thread. No worker or delayed mutation is created.
                if (!server.isSameThread()) return;
                ServerPlayer current = server.getPlayerList().getPlayer(playerId);
                if (current != null) current.sendSystemMessage(Component.literal("MMMM fixture job=" + ticket.id()
                        + " status=" + ticket.observe().get("status") + " error=" + ticket.observe().get("errorCode")));
            });
            return 1;
        });
    }

    private int cancel(CommandContext<CommandSourceStack> command) {
        return execute(command, player -> {
            String id = StringArgumentType.getString(command, "jobId");
            if (id.length() > 128) throw new LegacyCounterException("INVALID_ARGUMENT", "The job ID exceeds its bound");
            LegacyCounterApi.JobTicket ticket = commandTickets.get(id);
            if (ticket == null) throw new LegacyCounterException("COUNTER_JOB_UNKNOWN", "The command does not own that original ticket");
            boolean stopped = LegacyCounterApi.cancel(ticket, executor(player), dimension(player));
            player.sendSystemMessage(Component.literal("MMMM fixture job=" + id + " stopConfirmed=" + stopped + "; the original counter change remains"));
            return stopped ? 1 : 0;
        });
    }

    private static int execute(CommandContext<CommandSourceStack> command, PlayerCommand action) {
        ServerPlayer player = command.getSource().getPlayer();
        if (player == null) return 0;
        try { return action.execute(player); }
        catch (LegacyCounterException failure) {
            player.sendSystemMessage(Component.literal("MMMM fixture failed: " + failure.code()));
            return 0;
        }
    }
    private static boolean admin(CommandSourceStack source) { return source.getPermissionContext().permissionLevel() == PermissionLevel.ADMINS; }
    private static int integer(CommandContext<CommandSourceStack> command, String name) { return IntegerArgumentType.getInteger(command, name); }
    private static String executor(ServerPlayer player) { return "player-" + player.getUUID(); }
    private static String dimension(ServerPlayer player) { return player.level().dimension().identifier().toString(); }
    private interface PlayerCommand { int execute(ServerPlayer player); }
}
