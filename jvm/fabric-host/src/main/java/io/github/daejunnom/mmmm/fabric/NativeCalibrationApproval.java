package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.AnonymousBridge;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/** 실제 anonymous authority가 설치한 유한 recipe 전용 route이며 일반 write profile을 발급하지 않는다. */
final class NativeCalibrationApproval implements HostDispatcher.PurposeRoute, AutoCloseable {
    static final String PURPOSE = "numeric_calibration_normative47/1";
    static final Set<String> READ_PERMISSIONS = Set.of("mmmm:world_read", "mmmm:command_complete", "mmmm:provider_inventory");
    private static final Set<String> MANIFEST_FIELDS = Set.of("kind", "purpose", "selectionDigest", "hostEpoch", "registryGeneration",
            "runtimeSourceFactsDigest", "suiteDigest", "recipeSha256", "plan", "programs");
    private static final Set<String> PROGRAM_FIELDS = Set.of("stepId", "caseId", "functionId", "command", "programDigest",
            "sourceSha256", "sourceBytesHex", "readbackAddresses");
    private final ContractJson contracts;
    private final HostSession session;
    private final Clock clock;
    // 일반 route에 노출하거나 prepare에서 소비하지 않는다. one-operation/step binding은 기존 구현이 소유한다.
    private final NativePlanApproval plan;
    private final ObjectNode manifest;
    private final String manifestDigest;
    private final Map<String, Program> programs = new HashMap<>();
    private final Map<String, ObjectNode> steps = new HashMap<>();
    private final Map<String, Accepted> accepted = new ConcurrentHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean activated = new AtomicBoolean();
    private final Tasks tasks;
    private final Current current;
    private final Consumer<Invocation> retainAccepted;
    private final Runner runner;

    interface Tasks { <T> CompletionStage<T> submit(Supplier<T> action); }
    @FunctionalInterface interface Current {
        void check(HostSession session, ObjectNode context, Runnable original, boolean observeSources);
    }
    /** 실제 finite runner만 주입한다. absent runner를 성공 handler나 inspect 실행으로 대체하지 않는다. */
    interface Runner {
        ObjectNode ready(Invocation original, Program program, Control control);
        CompletionStage<ProviderResult> execute(Invocation original, Program program, Control control);
        CompletionStage<ObjectNode> poll(Invocation original, Control control);
        CompletionStage<ObjectNode> cancel(Invocation original, Control control);
        NativeCalibrationSource.IssuedReceipt lookup(Invocation original, Control control);
    }
    static final class Control {
        private final Runnable check;
        private final AtomicBoolean cancellation;
        private Control(Runnable check, AtomicBoolean cancellation) { this.check = check; this.cancellation = cancellation; }
        void checkpoint() { check.run(); }
        boolean cancellationRequested() { return cancellation.get(); }
    }
    static final class Program {
        private final ObjectNode value;
        private final byte[] sourceBytes;
        private Program(ObjectNode value, byte[] sourceBytes) { this.value = value.deepCopy(); this.sourceBytes = sourceBytes; }
        String stepId() { return text(value, "stepId"); }
        String caseId() { return text(value, "caseId"); }
        String functionId() { return text(value, "functionId"); }
        String command() { return text(value, "command"); }
        String programDigest() { return text(value, "programDigest"); }
        String sourceSha256() { return text(value, "sourceSha256"); }
        byte[] sourceBytes() { return sourceBytes.clone(); }
        ObjectNode readbackAddresses() { return ContractJson.object(value.path("readbackAddresses")).deepCopy(); }
    }
    private static final class Accepted {
        private final Invocation original;
        private final String digest;
        private final AtomicBoolean cancellation = new AtomicBoolean();
        private final CompletableFuture<ProviderResult> result = new CompletableFuture<>();
        private Accepted(Invocation original) { this.original = original; digest = ContractJson.digest(original.wire()); }
    }

    NativeCalibrationApproval(ContractJson contracts, ObjectNode input, HostSession session, Clock clock,
                              Tasks tasks, Current current, Consumer<Invocation> retainAccepted, Runner runner) {
        this.contracts = Objects.requireNonNull(contracts); this.session = Objects.requireNonNull(session); this.clock = Objects.requireNonNull(clock);
        this.tasks = Objects.requireNonNull(tasks); this.current = Objects.requireNonNull(current);
        this.retainAccepted = Objects.requireNonNull(retainAccepted); this.runner = runner;
        byte[] bytes = ContractJson.bytes(input);
        if (bytes.length > AnonymousBridge.MAX_FRAME) throw invalid();
        manifest = ContractJson.object(ContractJson.parse(bytes)); nodeLimit(manifest);
        HostDispatcher.exactFields(manifest, MANIFEST_FIELDS);
        if (!"native_calibration_approval".equals(text(manifest, "kind")) || !PURPOSE.equals(text(manifest, "purpose"))
                || !session.epoch().equals(text(manifest, "hostEpoch")) || session.verifiedWriteProfile()) throw invalid();
        for (String field : Set.of("selectionDigest", "runtimeSourceFactsDigest", "suiteDigest", "recipeSha256")) sha(manifest, field);
        if (!text(manifest, "suiteDigest").equals(text(manifest, "recipeSha256"))
                || !text(manifest, "registryGeneration").matches("[1-9][0-9]{0,18}")) throw invalid();
        try { if (Long.parseLong(text(manifest, "registryGeneration")) <= 0) throw invalid(); }
        catch (NumberFormatException failure) { throw invalid(); }
        ObjectNode inner = ContractJson.object(manifest.path("plan"));
        if (!inner.path("nativeExecutions").isArray() || !inner.path("nativeExecutions").isEmpty()
                || !inner.path("steps").isArray() || inner.path("steps").size() != 47
                || !manifest.path("programs").isArray() || manifest.path("programs").size() != 47) throw invalid();
        plan = new NativePlanApproval(contracts, inner, clock); plan.checkSession(session);
        for (JsonNode value : inner.path("steps")) {
            ObjectNode step = ContractJson.object(value);
            if (!"mmmm:command_execute".equals(text(step, "actionId"))) throw invalid();
            steps.put(text(step, "stepId"), step.deepCopy());
        }
        Set<String> cases = new HashSet<>(), functions = new HashSet<>(); int totalBytes = 0;
        for (JsonNode value : manifest.path("programs")) {
            ObjectNode program = ContractJson.object(value); HostDispatcher.exactFields(program, PROGRAM_FIELDS);
            String step = text(program, "stepId"), caseId = text(program, "caseId"), function = text(program, "functionId");
            String hex = text(program, "sourceBytesHex");
            if (!steps.containsKey(step) || !caseId.matches("[a-z][a-z0-9_]{0,127}") || !cases.add(caseId)
                    || !function.matches("mmmm_calibration:[a-z0-9_./-]{1,256}") || !functions.add(function)
                    || !text(program, "command").equals("function " + function)
                    || hex.length() > 128 * 1024 || (hex.length() & 1) != 0 || !hex.matches("[a-f0-9]+")) throw invalid();
            byte[] source = HexFormat.of().parseHex(hex); totalBytes += source.length;
            if (totalBytes > 1024 * 1024) throw invalid();
            sha(program, "programDigest"); sha(program, "sourceSha256");
            if (!ContractJson.sha256(source).equals(text(program, "sourceSha256"))) throw invalid();
            ObjectNode addresses = ContractJson.object(program.path("readbackAddresses"));
            if (!caseId.equals(addresses.path("caseId").asText()) || !function.equals(addresses.path("function").asText())) throw invalid();
            ObjectNode arguments = ContractJson.newObject().put("command", text(program, "command"));
            if (!ContractJson.digest(arguments).equals(steps.get(step).path("argumentsDigest").asText())
                    || programs.putIfAbsent(step, new Program(program, source)) != null) throw invalid();
        }
        if (!programs.keySet().equals(steps.keySet())) throw invalid();
        manifestDigest = ContractJson.digest(manifest);
    }

    String selectionDigest() { return text(manifest, "selectionDigest"); }
    String manifestDigest() { return manifestDigest; }
    String registryGeneration() { return text(manifest, "registryGeneration"); }
    String runtimeSourceFactsDigest() { return text(manifest, "runtimeSourceFactsDigest"); }

    /** 원 private Complete/EOF 뒤 실제 host의 ADMIN·source 재검사가 끝난 경우만 호출한다. */
    void activateAfterBridge(HostSession owner, String selection, String digest, Runnable original) {
        original.run(); session.checkOpen();
        if (owner != session || closed.get() || !selectionDigest().equals(selection) || !manifestDigest.equals(digest)) throw invalid();
        String contextId = manifest.path("plan").path("contextPins").get(0).path("contextId").asText();
        current.check(session, session.context(contextId), original, false); original.run();
        if (!activated.compareAndSet(false, true)) throw invalid();
        try { original.run(); } catch (RuntimeException failure) { close(); throw failure; }
    }

    @Override public CompletionStage<ObjectNode> prepare(HostSession owner, Invocation invocation, HostDispatcher.InspectionControl request) {
        var result = new CompletableFuture<ObjectNode>(); request.whenStopped(() -> result.cancel(false));
        tasks.submit(() -> {
            try {
                Control control = control(owner, invocation, request, new AtomicBoolean(), false);
                check(invocation, control, true); Program program = validate(invocation);
                ObjectNode ready = checked(() -> {
                    ObjectNode value = requireRunner().ready(invocation, program, control); bounded(value); return value;
                }, () -> check(invocation, control, true));
                // 준비는 immutable pin 검증만 한다. 기존 NativePlanApproval의 sticky admission은 dispatch만 호출한다.
                result.complete(ready.deepCopy());
            } catch (RuntimeException | Error failure) { result.completeExceptionally(failure); }
            return null;
        }).whenComplete((ignored, failure) -> { if (failure != null) result.completeExceptionally(failure); });
        return result.minimalCompletionStage();
    }

    @Override public CompletionStage<ProviderResult> dispatch(HostSession owner, Invocation invocation, HostDispatcher.InspectionControl request) {
        var result = new CompletableFuture<ProviderResult>(); var active = new AtomicReference<Accepted>();
        request.whenStopped(() -> { if (!result.isDone()) { Accepted original = active.get(); if (original != null) original.cancellation.set(true); result.cancel(false); } });
        tasks.submit(() -> {
            try {
                Control admission = control(owner, invocation, request, new AtomicBoolean(), false);
                check(invocation, admission, true); Program program = validate(invocation); Runner actual = requireRunner();
                checked(() -> { bounded(actual.ready(invocation, program, admission)); return null; },
                        () -> check(invocation, admission, true));
                Accepted previous = accepted.get(invocation.invocationId());
                if (previous != null) {
                    if (!previous.digest.equals(ContractJson.digest(invocation.wire()))) throw invalid();
                    active.set(previous); copy(previous.result, result); return null;
                }
                if (accepted.size() == 47) throw invalid();
                plan.checkInvocation(session, invocation, true);
                retainAccepted.accept(invocation);
                Accepted admitted = new Accepted(invocation); accepted.put(invocation.invocationId(), admitted); active.set(admitted);
                Control execution = control(owner, invocation, request, admitted.cancellation, false);
                copy(admitted.result, result);
                CompletionStage<ProviderResult> stage = stage(() -> actual.execute(invocation, program, execution),
                        () -> check(invocation, execution, true));
                finishStage(stage, admitted.result, value -> {
                    if (value == null) throw invalid(); bounded(value.wire()); contracts.validate("ProviderResult", value.wire()); return value;
                }, () -> check(invocation, execution, true));
            } catch (RuntimeException | Error failure) {
                Accepted admitted = active.get(); if (admitted != null) admitted.result.completeExceptionally(failure);
                result.completeExceptionally(failure);
            }
            return null;
        }).whenComplete((ignored, failure) -> { if (failure != null) result.completeExceptionally(failure); });
        return result.minimalCompletionStage();
    }

    @Override public CompletionStage<ObjectNode> poll(HostSession owner, String id, HostDispatcher.InspectionControl request) { return query(owner, id, request, false); }
    @Override public CompletionStage<ObjectNode> cancel(HostSession owner, String id, HostDispatcher.InspectionControl request) { return query(owner, id, request, true); }

    private CompletionStage<ObjectNode> query(HostSession owner, String id, HostDispatcher.InspectionControl request, boolean cancel) {
        var result = new CompletableFuture<ObjectNode>(); request.whenStopped(() -> result.cancel(false));
        tasks.submit(() -> {
            try {
                Accepted original = requireAccepted(owner, id); Control control = control(owner, original.original, request, original.cancellation, true);
                check(original.original, control, true); plan.checkInvocation(session, original.original, false); Runner actual = requireRunner();
                if (cancel) original.cancellation.set(true);
                CompletionStage<ObjectNode> stage = stage(() -> cancel ? actual.cancel(original.original, control) : actual.poll(original.original, control),
                        () -> check(original.original, control, true));
                finishStage(stage, result, value -> { bounded(value); return value.deepCopy(); },
                        () -> check(original.original, control, true));
            } catch (RuntimeException | Error failure) { result.completeExceptionally(failure); } return null;
        }).whenComplete((ignored, failure) -> { if (failure != null) result.completeExceptionally(failure); });
        return result.minimalCompletionStage();
    }

    NativeCalibrationSource.IssuedReceipt lookup(HostSession owner, ObjectNode context, String id, HostDispatcher.InspectionControl request) {
        Accepted original = requireAccepted(owner, id);
        if (!context.equals(original.original.context())) throw invalid();
        Control control = control(owner, original.original, request, original.cancellation, true);
        check(original.original, control, false); plan.checkInvocation(session, original.original, false);
        return checked(() -> requireRunner().lookup(original.original, control),
                () -> check(original.original, control, false));
    }

    private Accepted requireAccepted(HostSession owner, String id) {
        if (owner != session) throw invalid(); session.checkOpen(); if (closed.get()) throw invalid();
        requireActivated();
        Accepted original = accepted.get(id);
        if (original == null) throw new ContractException("INVOCATION_UNKNOWN", "이 calibration route가 수락한 원 Invocation이 없습니다");
        return original;
    }
    private Control control(HostSession owner, Invocation invocation, HostDispatcher.InspectionControl request, AtomicBoolean cancellation, boolean controlQuery) {
        return new Control(() -> {
            request.checkpoint(); if (owner != session || closed.get()) throw invalid(); session.checkOpen();
            requireActivated();
            if (!controlQuery && cancellation.get()) throw new ContractException("CANCELLATION_REQUESTED", "원 calibration Invocation이 취소되었습니다");
            if (!controlQuery && !clock.instant().isBefore(invocation.deadlineAt())) throw new ContractException("DEADLINE_EXCEEDED", "원 calibration Invocation 기한이 끝났습니다");
            current.check(session, invocation.context(), request::checkpoint, false); request.checkpoint();
        }, cancellation);
    }
    private void check(Invocation invocation, Control control, boolean sources) {
        control.checkpoint(); current.check(session, invocation.context(), control::checkpoint, sources); control.checkpoint();
    }
    private Program validate(Invocation invocation) {
        if (!clock.instant().isBefore(plan.expiresAt()) || !invocation.context().equals(session.context(invocation.contextId()))
                || ContractJson.bytes(invocation.wire()).length > HostRuntime.MAX_RESULT_BYTES) throw invalid();
        ObjectNode step = steps.get(invocation.stepId()); Program program = programs.get(invocation.stepId());
        if (step == null || program == null) throw invalid();
        for (String field : Set.of("bindingId", "actionId", "actionDigest", "implementationDigest", "argumentsDigest", "contextDigest")) {
            if (!step.path(field).equals(invocation.wire().path(field))) throw invalid();
        }
        if (!step.path("contextId").asText().equals(invocation.contextId())) throw invalid();
        HostDispatcher.exactFields(invocation.arguments(), Set.of("command"));
        if (!program.command().equals(invocation.arguments().path("command").asText())) throw invalid();
        return program;
    }
    private Runner requireRunner() {
        if (runner == null) throw new ContractException("CALIBRATION_RUNNER_UNAVAILABLE", "실제 loaded-function calibration runner가 설치되지 않았습니다");
        return runner;
    }
    private void requireActivated() {
        if (!activated.get()) throw new ContractException("CALIBRATION_APPROVAL_PENDING", "원 private 승인 ACK와 EOF가 완료되지 않았습니다");
    }
    private static <T> void copy(CompletionStage<T> source, CompletableFuture<T> destination) {
        source.whenComplete((value, failure) -> { if (failure != null) destination.completeExceptionally(failure); else destination.complete(value); });
    }
    /** A stage failure stays primary even when the same request's final checks fail. */
    private static Throwable preserve(Throwable original, Throwable current) {
        if (original == null) return current;
        if (current != null && current != original) original.addSuppressed(current);
        return original;
    }
    private static Throwable postcheck(Throwable original, Runnable current) {
        try { current.run(); }
        catch (RuntimeException | Error failure) { return preserve(original, failure); }
        return original;
    }
    private static <T> T checked(Supplier<T> action, Runnable current) {
        T value = null; Throwable original = null;
        try { value = action.get(); }
        catch (RuntimeException | Error failure) { original = failure; }
        Throwable terminal = postcheck(original, current);
        if (terminal instanceof RuntimeException failure) throw failure;
        if (terminal instanceof Error failure) throw failure;
        return value;
    }
    private static <T> CompletionStage<T> stage(Supplier<CompletionStage<T>> action, Runnable current) {
        try {
            CompletionStage<T> result = action.get(); if (result == null) throw invalid(); return result;
        } catch (RuntimeException | Error original) {
            postcheck(original, current); throw original;
        }
    }
    private static <T> void completeChecked(CompletableFuture<T> result, Throwable stageFailure,
                                            Supplier<T> value, Runnable current) {
        T checked = null; Throwable original = stageFailure;
        if (original == null) {
            try { checked = value.get(); }
            catch (RuntimeException | Error failure) { original = failure; }
        }
        Throwable terminal = postcheck(original, current);
        if (terminal != null) result.completeExceptionally(terminal); else result.complete(checked);
    }
    private <T> void finishStage(CompletionStage<T> stage, CompletableFuture<T> result,
                                 Function<T, T> value, Runnable current) {
        try {
            stage.whenComplete((observed, original) -> {
                try {
                    CompletionStage<Void> task = tasks.submit(() -> {
                        completeChecked(result, original, () -> value.apply(observed), current); return null;
                    });
                    if (task == null) throw invalid();
                    task.whenComplete((ignored, terminal) -> {
                        if (terminal != null) result.completeExceptionally(postcheck(preserve(original, terminal), current));
                    });
                } catch (RuntimeException | Error terminal) {
                    result.completeExceptionally(postcheck(preserve(original, terminal), current));
                }
            });
        } catch (RuntimeException | Error terminal) {
            result.completeExceptionally(postcheck(terminal, current));
        }
    }
    private static void bounded(JsonNode value) {
        if (value == null || ContractJson.bytes(value).length > HostRuntime.MAX_RESULT_BYTES) throw invalid();
    }
    private static void nodeLimit(JsonNode root) {
        var pending = new ArrayDeque<JsonNode>(); pending.push(root); int nodes = 0;
        while (!pending.isEmpty()) {
            JsonNode node = pending.pop(); if (++nodes > 4096) throw invalid();
            if (node.isContainerNode()) node.elements().forEachRemaining(pending::push);
        }
    }
    private static String text(ObjectNode value, String key) { return HostDispatcher.string(value, key); }
    private static void sha(ObjectNode value, String key) { if (!text(value, key).matches("[a-f0-9]{64}")) throw invalid(); }
    private static ContractException invalid() { return new ContractException("CALIBRATION_APPROVAL_MISMATCH", "유한 calibration 승인이 원 route 또는 Invocation과 일치하지 않습니다"); }
    @Override public void close() { closed.set(true); accepted.values().forEach(value -> { value.cancellation.set(true); value.result.cancel(false); }); }
}
