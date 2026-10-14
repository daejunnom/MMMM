package io.github.daejunnom.mmmm.fixture.legacy;

import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.permissions.PermissionLevel;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletionStage;

/** SDK-free public methods. Exact public profiles still require independent MMMM source and context admission. */
public final class LegacyCounterApi {
    private record Session(MinecraftServer server, CounterEngine engine) { }
    private static volatile Session session;
    private LegacyCounterApi() { }

    public static final class JobTicket {
        private final CounterEngine.Job job;
        private JobTicket(CounterEngine.Job job) { this.job = job; }
        public String id() { return job.id(); }
        public CompletionStage<Map<String, Object>> stage() { return job.stage(); }
        /** Immutable facts captured by the original call. This is not a fresh readback or a recovery grant. */
        public Map<String, Object> observe() { return job.observation(); }
    }

    public static int read(String executorHandle, String dimension) {
        return current().engine.read(executorHandle, dimension);
    }

    public static Map<String, Object> observe(String executorHandle, String dimension) {
        return current().engine.snapshot(executorHandle, dimension);
    }

    public static int set(String executorHandle, String dimension, int expected, int value, String fault) {
        return current().engine.set(executorHandle, dimension, expected, value, fault);
    }

    public static CompletionStage<Map<String, Object>> job(String executorHandle, String dimension,
            int expected, int value, int delayTicks, String fault) {
        return beginJob(executorHandle, dimension, expected, value, delayTicks, fault).stage();
    }

    /** A fixture-local control object. Generic public Java profiles cannot construct or authorize it. */
    public static JobTicket beginJob(String executorHandle, String dimension, int expected, int value,
            int delayTicks, String fault) {
        return new JobTicket(current().engine.beginJob(executorHandle, dimension, expected, value, delayTicks, fault));
    }

    public static boolean cancel(JobTicket ticket, String executorHandle, String dimension) {
        if (ticket == null) throw new LegacyCounterException("INVALID_ARGUMENT", "A native fixture ticket is required");
        return current().engine.cancel(ticket.job, executorHandle, dimension);
    }

    static void start(MinecraftServer server) {
        if (!server.isSameThread()) throw new LegacyCounterException("WRONG_THREAD", "Fixture startup requires the server thread");
        if (session != null) throw new LegacyCounterException("SESSION_ALREADY_ACTIVE", "A fixture server session is already active");
        CounterEngine engine = new CounterEngine("fixture-" + UUID.randomUUID(),
                (executor, dimension, write) -> check(server, executor, dimension, write));
        session = new Session(server, engine);
    }

    static void tick(MinecraftServer server) {
        Session current = session;
        if (current != null && current.server == server) current.engine.tick();
    }

    static void stop(MinecraftServer server) {
        Session current = session;
        if (current == null || current.server != server) return;
        current.engine.stop();
        session = null;
    }

    private static Session current() {
        Session current = session;
        if (current == null) throw new LegacyCounterException("SESSION_ENDED", "No active fixture server session exists");
        if (!current.server.isSameThread()) throw new LegacyCounterException("WRONG_THREAD", "Fixture API requires the actual server thread");
        return current;
    }

    private static void check(MinecraftServer server, String executorHandle, String dimension, boolean write) {
        Session current = session;
        if (current == null || current.server != server || !server.isSameThread()) throw new LegacyCounterException("SESSION_ENDED", "The original fixture server session is no longer current");
        ServerPlayer player = server.getPlayerList().getPlayer(UUID.fromString(executorHandle.substring(7)));
        if (player == null) throw new LegacyCounterException("EXECUTOR_DISCONNECTED", "The actual fixture player disconnected");
        if (!player.level().dimension().identifier().toString().equals(dimension)) throw new LegacyCounterException("CONTEXT_DRIFT", "The actual player dimension differs from the original target");
        if (write && player.createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) {
            throw new LegacyCounterException("PERMISSION_DENIED", "Fixture writes and cancellation require a connected actual administrator");
        }
    }
}
