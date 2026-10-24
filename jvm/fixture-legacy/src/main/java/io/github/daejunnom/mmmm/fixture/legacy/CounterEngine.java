package io.github.daejunnom.mmmm.fixture.legacy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/** Session-local fixture state. It owns no MMMM project, durable journal or game-world rollback. */
final class CounterEngine {
    static final int MAX_CELLS = 64;
    static final int MAX_JOBS = 16;
    static final int MAX_DELAY_TICKS = 200;
    static final int MAX_COUNTER = 10_000;

    interface Guard { void check(String executorHandle, String dimension, boolean write); }
    private enum Fault { NONE, BEFORE_MUTATION, LOST_RESPONSE, LATE_COMPLETION }
    private record Key(String executorHandle, String dimension) { }
    private record Cell(int value, long revision, long mutationCount) { }

    static final class Job {
        private final CounterEngine owner;
        private final Key key;
        private final String id;
        private final long dueTick;
        private final Fault fault;
        private final Map<String, Object> before;
        private final Map<String, Object> after;
        private final boolean mutationStarted;
        private final CompletableFuture<Map<String, Object>> completion = new CompletableFuture<>();
        private final CompletionStage<Map<String, Object>> stage = completion.minimalCompletionStage();
        private volatile Map<String, Object> observation;
        private boolean cancellationRequested;
        private boolean terminal;

        private Job(CounterEngine owner, Key key, String id, long dueTick, Fault fault,
                    Map<String, Object> before, Map<String, Object> after, boolean mutationStarted) {
            this.owner = owner; this.key = key; this.id = id; this.dueTick = dueTick; this.fault = fault;
            this.before = before; this.after = after; this.mutationStarted = mutationStarted;
            observe("accepted", false, "");
        }

        String id() { return id; }
        CompletionStage<Map<String, Object>> stage() { return stage; }
        Map<String, Object> observation() { return observation; }

        private void observe(String status, boolean stopConfirmed, String errorCode) {
            observation = Map.of("format", "mmmm.fixture.counter-job/1", "jobId", id,
                    "status", status, "cancellationRequested", cancellationRequested,
                    "stopConfirmed", stopConfirmed, "mutationStarted", mutationStarted,
                    "before", before, "after", after, "errorCode", errorCode);
        }

        private void finish(String status, String errorCode) {
            if (terminal) return;
            terminal = true;
            String code = "cancelled".equals(status) && errorCode.isEmpty() ? "COUNTER_JOB_CANCELLED" : errorCode;
            observe(status, true, code);
            if ("complete".equals(status)) completion.complete(Map.of("value", after.get("value")));
            else completion.completeExceptionally(new LegacyCounterException(code, "The fixture delivery stopped; the original counter effect remains in its captured facts"));
        }

        private void fail(String code, String message) {
            if (terminal) return;
            terminal = true;
            observe("failed", true, code);
            completion.completeExceptionally(new LegacyCounterException(code, message));
        }
    }

    private final Thread ownerThread = Thread.currentThread();
    private final String session;
    private final Guard guard;
    private final Map<Key, Cell> cells = new LinkedHashMap<>();
    private final Map<String, Job> jobs = new LinkedHashMap<>();
    private boolean active = true;
    private long tick;
    private long sequence;

    CounterEngine(String session, Guard guard) {
        if (session == null || session.length() > 88 || !session.matches("fixture-[a-zA-Z0-9-]{1,80}")) throw invalid();
        this.session = session;
        this.guard = Objects.requireNonNull(guard);
    }

    int read(String executorHandle, String dimension) { return (int) snapshot(executorHandle, dimension).get("value"); }

    Map<String, Object> snapshot(String executorHandle, String dimension) {
        Key key = checked(executorHandle, dimension, false);
        return snapshot(key);
    }

    int set(String executorHandle, String dimension, int expected, int value, String faultName) {
        Key key = checked(executorHandle, dimension, true);
        Fault fault = fault(faultName);
        if (fault == Fault.LATE_COMPLETION) throw invalid();
        validateValues(expected, value);
        Cell previous = current(key);
        compare(previous, expected);
        if (fault == Fault.BEFORE_MUTATION) throw failure("COUNTER_BEFORE_MUTATION", "The explicit fixture fault rejected the write before mutation");
        mutate(key, previous, value);
        if (fault == Fault.LOST_RESPONSE) throw failure("COUNTER_RESPONSE_LOST", "The counter changed before the explicit fixture response fault");
        return value;
    }

    Job beginJob(String executorHandle, String dimension, int expected, int value, int delayTicks, String faultName) {
        Key key = checked(executorHandle, dimension, true);
        Fault fault = fault(faultName);
        validateValues(expected, value);
        if (delayTicks < 0 || delayTicks > MAX_DELAY_TICKS) throw invalid();
        if (jobs.size() >= MAX_JOBS) throw failure("COUNTER_JOB_LIMIT", "The active fixture job limit was reached");
        if (sequence == Long.MAX_VALUE || tick > Long.MAX_VALUE - delayTicks) throw failure("COUNTER_LIMIT", "The fixture sequence or tick limit was reached");
        Cell previous = current(key);
        compare(previous, expected);
        if (fault == Fault.BEFORE_MUTATION) throw failure("COUNTER_BEFORE_MUTATION", "The explicit fixture fault rejected the job before mutation");
        Map<String, Object> before = snapshot(key);
        // The sole mutation is synchronous under the original native permission check. Ticks only deliver a result.
        boolean changed = mutate(key, previous, value);
        Job job = new Job(this, key, session + "-job-" + ++sequence, tick + delayTicks, fault,
                before, snapshot(key), changed);
        jobs.put(job.id, job);
        if (delayTicks == 0) deliver(job);
        return job;
    }

    boolean cancel(Job job, String executorHandle, String dimension) {
        Key key = checked(executorHandle, dimension, true);
        if (job == null || job.owner != this || !job.key.equals(key)) throw failure("COUNTER_JOB_SCOPE", "The ticket belongs to another session or target");
        if (job.terminal) return true;
        job.cancellationRequested = true;
        if (job.fault == Fault.LATE_COMPLETION) {
            job.observe("accepted", false, "");
            return false;
        }
        jobs.remove(job.id);
        job.finish("cancelled", "");
        return true;
    }

    void tick() {
        requireOwner();
        if (tick == Long.MAX_VALUE) throw failure("COUNTER_LIMIT", "The fixture tick limit was reached");
        tick++;
        for (Job job : new ArrayList<>(jobs.values())) if (job.dueTick <= tick) deliver(job);
    }

    void stop() {
        requireOwnerThread();
        if (!active) return;
        active = false;
        for (Job job : new ArrayList<>(jobs.values())) {
            job.cancellationRequested = true;
            job.finish("cancelled", "SESSION_ENDED");
        }
        jobs.clear(); cells.clear();
    }

    private void deliver(Job job) {
        // Earlier completion callbacks can synchronously cancel another due ticket in this same tick.
        if (job.terminal || jobs.get(job.id) != job) return;
        requireOwner();
        jobs.remove(job.id);
        try {
            guard.check(job.key.executorHandle, job.key.dimension, false);
            if (job.fault == Fault.LOST_RESPONSE) job.fail("COUNTER_RESPONSE_LOST", "The original counter change completed before the response fault");
            else job.finish("complete", "");
        } catch (LegacyCounterException failure) {
            job.fail(failure.code(), failure.getMessage());
        } catch (RuntimeException failure) {
            // A platform callback failure ends this pending delivery; it does not erase the earlier mutation.
            job.fail("COUNTER_GUARD_FAILED", "The current native fixture context could not be checked");
        }
    }

    private boolean mutate(Key key, Cell previous, int value) {
        if (previous.value == value) return false;
        if (!cells.containsKey(key) && cells.size() >= MAX_CELLS) throw failure("COUNTER_CELL_LIMIT", "The session fixture cell limit was reached");
        if (previous.revision == Long.MAX_VALUE || previous.mutationCount == Long.MAX_VALUE) throw failure("COUNTER_LIMIT", "The counter revision limit was reached");
        cells.put(key, new Cell(value, previous.revision + 1, previous.mutationCount + 1));
        return true;
    }

    private Map<String, Object> snapshot(Key key) {
        Cell cell = current(key);
        return Map.of("format", "mmmm.fixture.counter/1", "value", cell.value,
                "revision", cell.revision, "mutationCount", cell.mutationCount,
                "session", session, "tick", tick, "executorHandle", key.executorHandle, "dimension", key.dimension);
    }

    private Cell current(Key key) { return cells.getOrDefault(key, new Cell(0, 0, 0)); }
    private Key checked(String executorHandle, String dimension, boolean write) {
        requireOwner();
        if (executorHandle == null || executorHandle.length() != 43 || !executorHandle.startsWith("player-")) throw invalid();
        try {
            String uuid = executorHandle.substring(7);
            if (!UUID.fromString(uuid).toString().equals(uuid)) throw invalid();
        } catch (IllegalArgumentException failure) { throw invalid(); }
        if (dimension == null || dimension.length() > 256 || !dimension.matches("[a-z0-9_.-]+:[a-z0-9/._-]+")) throw invalid();
        guard.check(executorHandle, dimension, write);
        return new Key(executorHandle, dimension);
    }
    private void requireOwner() {
        requireOwnerThread();
        if (!active) throw failure("SESSION_ENDED", "The fixture server session ended");
    }
    private void requireOwnerThread() {
        if (Thread.currentThread() != ownerThread) throw failure("WRONG_THREAD", "Fixture state requires its actual owner thread");
    }
    private static Fault fault(String name) {
        if (name == null || name.length() > 32) throw invalid();
        return switch (name) {
            case "none" -> Fault.NONE;
            case "before_mutation" -> Fault.BEFORE_MUTATION;
            case "lost_response" -> Fault.LOST_RESPONSE;
            case "late_completion" -> Fault.LATE_COMPLETION;
            default -> throw invalid();
        };
    }
    private static void validateValues(int expected, int value) {
        if (expected < 0 || expected > MAX_COUNTER || value < 0 || value > MAX_COUNTER) throw invalid();
    }
    private static void compare(Cell actual, int expected) {
        if (actual.value != expected) throw failure("COUNTER_CONFLICT", "The actual counter differs from the expected value");
    }
    private static LegacyCounterException invalid() { return failure("INVALID_ARGUMENT", "The fixture argument is outside its closed bounded contract"); }
    private static LegacyCounterException failure(String code, String message) { return new LegacyCounterException(code, message); }
}
