package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.AnonymousBridge;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.host.NativeInvocationReservations;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
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
            "sourceSha256", "sourceBytesHex", "targetBindings", "commands", "preseedEndIndex",
            "selectedCommandStageIndex", "initializationCommands", "cleanupCommands");
    private static final int MAX_RECIPE_COMMANDS = 4096;
    private static final int MAX_COMMAND_BYTES = 8192;
    private final ContractJson contracts;
    private final HostSession session;
    private final Clock clock;
    // 일반 route에 노출하거나 prepare에서 소비하지 않는다. one-operation/step binding은 기존 구현이 소유한다.
    private final NativePlanApproval plan;
    private final NativeInvocationReservations reservations;
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
        NativeCalibrationPrepared ready(Invocation original, Program program, Control control);
        CompletionStage<ProviderResult> execute(Invocation original, Program program, Control control);
        CompletionStage<ObjectNode> poll(Invocation original, Control control);
        CompletionStage<ObjectNode> cancel(Invocation original, Control control);
        NativeCalibrationRunFacts lookup(Invocation original, Control control);
    }
    @FunctionalInterface interface StateObserver {
        NativeCalibrationTargetImages.ImagePair observe(Invocation original, Program program, Control control);
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
        private final List<String> commands;
        private final List<String> initializationCommands;
        private final List<String> cleanupCommands;
        private final List<String> resourcesRead, resourcesWritten;
        private final List<TargetBinding> targetBindings;
        private Program(ObjectNode value, byte[] sourceBytes, List<String> commands,
                        List<String> initializationCommands, List<String> cleanupCommands,
                        ObjectNode step, ObjectNode context) {
            this.value = value.deepCopy(); this.sourceBytes = sourceBytes;
            this.commands = List.copyOf(commands); this.initializationCommands = List.copyOf(initializationCommands);
            this.cleanupCommands = List.copyOf(cleanupCommands);
            this.resourcesRead = footprint(step, "resourcesRead"); this.resourcesWritten = footprint(step, "resourcesWritten");
            this.targetBindings = NativeCalibrationApproval.targetBindings(value, step, context, resourcesRead, resourcesWritten);
        }
        String stepId() { return text(value, "stepId"); }
        String caseId() { return text(value, "caseId"); }
        String functionId() { return text(value, "functionId"); }
        String command() { return text(value, "command"); }
        String programDigest() { return text(value, "programDigest"); }
        String sourceSha256() { return text(value, "sourceSha256"); }
        byte[] sourceBytes() { return sourceBytes.clone(); }
        /** Rust sealed recipe의 비교 입력이다. 원 source를 재구성하거나 실행할 권한이 아니다. */
        List<String> commands() { return commands; }
        /** 원 commands의 exclusive prefix [0, end) 뒤에서 preseed를 capture한다. */
        int preseedEndIndex() { return value.path("preseedEndIndex").intValue(); }
        /** 원 commands 안의 zero-based arithmetic/finite-check site다. */
        int selectedCommandStageIndex() { return value.path("selectedCommandStageIndex").intValue(); }
        // 초기화·정리 원문도 비교 입력이며 이 accessor가 별도 실행이나 수명을 승인하지 않는다.
        List<String> initializationCommands() { return initializationCommands; }
        List<String> cleanupCommands() { return cleanupCommands; }
        List<String> resourcesRead() { return resourcesRead; }
        List<String> resourcesWritten() { return resourcesWritten; }
        List<TargetBinding> targetBindings() { return targetBindings; }
    }
    /** Closed typed associations; these are external targets, never resource ACL grants. */
    static final class TargetBinding {
        private final String targetId, kind, objective, storage, expectedDigest;
        private final List<String> ownedSubtrees;
        private TargetBinding(String targetId, String kind, String objective, String storage,
                              List<String> ownedSubtrees, String expectedDigest) {
            this.targetId = targetId; this.kind = kind; this.objective = objective; this.storage = storage;
            this.ownedSubtrees = List.copyOf(ownedSubtrees); this.expectedDigest = expectedDigest;
        }
        String targetId() { return targetId; } String kind() { return kind; }
        String objective() { return objective; } String storage() { return storage; }
        List<String> ownedSubtrees() { return ownedSubtrees; } String expectedDigest() { return expectedDigest; }
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
        if (!"native_calibration_approval/2".equals(text(manifest, "kind")) || !PURPOSE.equals(text(manifest, "purpose"))
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
        // Reuse the immutable projection parser, not its ordinary resource ACL.
        // The external target proof is checked separately for this purpose.
        plan = new NativePlanApproval(contracts, inner, clock);
        reservations = new NativeInvocationReservations(plan.expiresAt(), clock);
        checkInstalledContext(inner);
        for (JsonNode value : inner.path("steps")) {
            ObjectNode step = ContractJson.object(value);
            if (!"mmmm:calibration_command_execute".equals(text(step, "actionId"))) throw invalid();
            steps.put(text(step, "stepId"), step.deepCopy());
        }
        Set<String> cases = new HashSet<>(), functions = new HashSet<>(), targets = new HashSet<>(); int totalBytes = 0, totalCommands = 0;
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
            if (!ContractJson.sha256(source).equals(text(program, "sourceSha256"))
                    || !text(program, "programDigest").equals(text(program, "sourceSha256"))) throw invalid();
            List<String> commands = commandInputs(program, "commands", false);
            List<String> initialization = commandInputs(program, "initializationCommands", true);
            List<String> cleanup = commandInputs(program, "cleanupCommands", true);
            totalCommands += commands.size() + initialization.size() + cleanup.size();
            if (totalCommands > MAX_RECIPE_COMMANDS) throw invalid();
            int preseed = commandIndex(program, "preseedEndIndex"), selected = commandIndex(program, "selectedCommandStageIndex");
            if (preseed > selected || selected >= commands.size()) throw invalid();
            ObjectNode arguments = ContractJson.newObject().put("command", text(program, "command"));
            if (!ContractJson.digest(arguments).equals(steps.get(step).path("argumentsDigest").asText())) throw invalid();
            Program parsed = new Program(program, source, commands, initialization, cleanup,
                    steps.get(step), session.context(steps.get(step).path("contextId").asText()));
            for (TargetBinding target : parsed.targetBindings()) if (!targets.add(target.targetId())) throw invalid();
            if (programs.putIfAbsent(step, parsed) != null) throw invalid();
        }
        if (!programs.keySet().equals(steps.keySet())) throw invalid();
        manifestDigest = ContractJson.digest(manifest);
    }

    private void checkInstalledContext(ObjectNode inner) {
        session.checkOpen();
        if (!inner.path("contextPins").isArray() || inner.path("contextPins").size() != 1) throw invalid();
        ObjectNode pin = ContractJson.object(inner.path("contextPins").get(0));
        ObjectNode context = session.context(text(pin, "contextId"));
        if (!plan.principalId().equals(session.principalRef()) || !plan.principalId().equals(text(context, "principalRef"))
                || !plan.projectId().equals(text(context, "projectId")) || !plan.policyRevision().equals(text(context, "policyRevision"))
                || !pin.path("contextDigest").equals(context.path("contextDigest"))
                || !pin.path("environment").equals(context.path("environment"))) throw invalid();
        if (!clock.instant().isBefore(plan.expiresAt())) throw new ContractException("NATIVE_APPROVAL_EXPIRED", "The frozen plan approval has expired");
    }

    private static List<String> footprint(ObjectNode step, String field) {
        if (!step.path(field).isArray() || step.path(field).size() != 2) throw invalid();
        List<String> result = new ArrayList<>();
        for (JsonNode id : step.path(field)) {
            if (!id.isTextual() || !id.textValue().matches("[a-z0-9][a-z0-9._:-]{0,127}") || result.contains(id.textValue())) throw invalid();
            result.add(id.textValue());
        }
        return List.copyOf(result);
    }

    private static List<TargetBinding> targetBindings(ObjectNode program, ObjectNode step, ObjectNode context,
                                                       List<String> read, List<String> written) {
        if (!read.equals(written) || !program.path("targetBindings").isArray() || program.path("targetBindings").size() != 2
                || !step.path("preconditions").isArray() || step.path("preconditions").size() != 2) throw invalid();
        Map<String, String> expected = new HashMap<>();
        for (JsonNode value : step.path("preconditions")) {
            ObjectNode condition = ContractJson.object(value);
            if (!"resource_hash".equals(text(condition, "kind")) || !"full_target".equals(text(condition, "coverage"))) throw invalid();
            sha(condition, "expected");
            if (expected.putIfAbsent(text(condition, "subject"), text(condition, "expected")) != null) throw invalid();
        }
        List<TargetBinding> result = new ArrayList<>();
        for (int index = 0; index < 2; index++) {
            ObjectNode binding = ContractJson.object(program.path("targetBindings").get(index));
            boolean objective = index == 0;
            HostDispatcher.exactFields(binding, objective ? Set.of("targetId", "kind", "objective")
                    : Set.of("targetId", "kind", "storage", "ownedSubtrees"));
            String address = text(binding, objective ? "objective" : "storage");
            if (objective ? !address.matches("[a-zA-Z0-9_.-]{1,16}")
                    : address.length() > 256 || !address.matches("[a-z0-9_.-]+:[a-z0-9_./-]+")) throw invalid();
            String target = objective ? "calibration-objective-" + address
                    : "calibration-storage-" + ContractJson.sha256(address.getBytes(StandardCharsets.UTF_8));
            if (!target.equals(text(binding, "targetId")) || !target.equals(read.get(index))
                    || !expected.containsKey(target) || !context.path("scope").path("externalTargetIds").isArray()
                    || !contains(context.path("scope").path("externalTargetIds"), target)
                    || !(objective ? "objective" : "owned_storage").equals(text(binding, "kind"))) throw invalid();
            List<String> subtrees = List.of();
            if (!objective) {
                JsonNode trees = binding.path("ownedSubtrees");
                if (!trees.isArray() || trees.size() != 2 || !"inputs".equals(trees.get(0).asText())
                        || !"invocation".equals(trees.get(1).asText())) throw invalid();
                subtrees = List.of("inputs", "invocation");
            }
            result.add(new TargetBinding(target, objective ? "objective" : "owned_storage", objective ? address : null,
                    objective ? null : address, subtrees, expected.get(target)));
        }
        return List.copyOf(result);
    }
    private static boolean contains(JsonNode values, String expected) {
        for (JsonNode value : values) if (value.isTextual() && expected.equals(value.textValue())) return true;
        return false;
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
                NativeCalibrationPrepared ready = checked(() -> {
                    NativeCalibrationPrepared value = requireRunner().ready(invocation, program, control);
                    verifyPrepared(value, invocation, program, control); return value;
                }, () -> check(invocation, control, true));
                // 준비는 immutable pin 검증만 한다. 기존 NativePlanApproval의 sticky admission은 dispatch만 호출한다.
                ObjectNode wire = checked(() -> { ObjectNode value = ready.wire(control); bounded(value); return value; },
                        () -> check(invocation, control, true));
                result.complete(wire.deepCopy());
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
                Accepted previous = accepted.get(invocation.invocationId());
                if (previous != null) {
                    if (!previous.digest.equals(ContractJson.digest(invocation.wire()))) throw invalid();
                    requireReservation(invocation, true);
                    active.set(previous); copy(previous.result, result); return null;
                }
                NativeCalibrationPrepared prepared = checked(() -> actual.ready(invocation, program, admission),
                        () -> check(invocation, admission, true));
                Accepted admitted;
                synchronized (this) {
                    previous = accepted.get(invocation.invocationId());
                    if (previous != null) {
                        if (!previous.digest.equals(ContractJson.digest(invocation.wire()))) throw invalid();
                        requireReservation(invocation, true); active.set(previous); copy(previous.result, result); return null;
                    }
                    if (accepted.size() == 47) throw invalid();
                    checked(() -> { verifyPrepared(prepared, invocation, program, admission); return null; },
                            () -> check(invocation, admission, true));
                    NativeInvocationReservations.Candidate candidate = reservations.inspect(invocation, true);
                    reservations.admit(candidate);
                    admitted = new Accepted(invocation); accepted.put(invocation.invocationId(), admitted); active.set(admitted);
                    // A failing publication leaves the exact sticky claim and
                    // failed Accepted record; it cannot be rebound or executed.
                    retainAccepted.accept(invocation);
                }
                Control execution = control(owner, invocation, request, admitted.cancellation, false);
                copy(admitted.result, result);
                CompletionStage<ProviderResult> stage = stage(() -> actual.execute(invocation, program, execution),
                        () -> check(invocation, execution, true));
                finishStage(stage, admitted.result, value -> {
                    if (value == null) throw invalid(); bounded(value.wire()); contracts.validate("ProviderResult", value.wire());
                    if ("complete".equals(value.status())) {
                        if (!"unknown".equals(value.effects())) throw invalid();
                        nativeOutput(value.data());
                    } else if (!"failed".equals(value.status())) throw invalid();
                    return value;
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
                check(original.original, control, true); requireReservation(original.original, false); Runner actual = requireRunner();
                if (cancel) original.cancellation.set(true);
                CompletionStage<ObjectNode> stage = stage(() -> cancel ? actual.cancel(original.original, control) : actual.poll(original.original, control),
                        () -> check(original.original, control, true));
                finishStage(stage, result, value -> { bounded(value); return value.deepCopy(); },
                        () -> check(original.original, control, true));
            } catch (RuntimeException | Error failure) { result.completeExceptionally(failure); } return null;
        }).whenComplete((ignored, failure) -> { if (failure != null) result.completeExceptionally(failure); });
        return result.minimalCompletionStage();
    }

    NativeCalibrationRunFacts lookup(HostSession owner, ObjectNode context, String id, HostDispatcher.InspectionControl request) {
        Accepted original = requireAccepted(owner, id);
        if (!context.equals(original.original.context())) throw invalid();
        Control control = control(owner, original.original, request, original.cancellation, true);
        check(original.original, control, false); requireReservation(original.original, false);
        return checked(() -> requireRunner().lookup(original.original, control),
                () -> check(original.original, control, false));
    }

    /** An original Accepted query only; it cannot prepare, admit or run another Invocation. */
    NativeCalibrationTargetImages.ImagePair observeState(HostSession owner, ObjectNode context, String id, String digest,
                                                        HostDispatcher.InspectionControl request, StateObserver observer) {
        Accepted original = requireAccepted(owner, id);
        if (!original.digest.equals(digest) || !original.original.context().equals(context) || observer == null) throw invalid();
        Program program = programs.get(original.original.stepId()); if (program == null) throw invalid();
        Control control = control(owner, original.original, request, original.cancellation, true);
        check(original.original, control, true); requireReservation(original.original, false);
        return checked(() -> {
            NativeCalibrationTargetImages.ImagePair images = observer.observe(original.original, program, control);
            if (images == null || !program.targetBindings().get(0).targetId().equals(images.objectiveTargetId())
                    || !program.targetBindings().get(1).targetId().equals(images.storageTargetId())
                    || !ContractJson.sha256(images.objectiveBytes()).equals(images.objectiveSha256())
                    || !ContractJson.sha256(images.storageBytes()).equals(images.storageSha256())
                    || images.observedToTick() < images.observedFromTick()) throw invalid();
            // This is a fresh after/history image. Never compare it with the
            // frozen before condition or replace the Prepared before image.
            return images;
        }, () -> check(original.original, control, true));
    }

    /** Factual callback reporting is separate from recipe correctness and readback. */
    private static void nativeOutput(ObjectNode output) {
        HostDispatcher.exactFields(output, Set.of("completionClaim", "nativeCallbackCount", "nativeCallbackReturn"));
        JsonNode count = output.path("nativeCallbackCount"), returned = output.path("nativeCallbackReturn");
        if (!"native_function_queue_observed".equals(text(output, "completionClaim")) || !count.isIntegralNumber()
                || !count.canConvertToInt() || count.intValue() < 0 || count.intValue() > 256
                || (count.intValue() == 1 ? !returned.isIntegralNumber() || !returned.canConvertToInt() : !returned.isNull())) throw invalid();
    }

    private void requireReservation(Invocation original, boolean write) {
        if (!reservations.containsExact(original)) throw invalid();
        reservations.inspect(original, write);
    }
    private void verifyPrepared(NativeCalibrationPrepared prepared, Invocation original, Program program, Control control) {
        if (prepared == null) throw invalid();
        prepared.checkCurrent(original, program, control);
        if (!ContractJson.digest(original.wire()).equals(prepared.invocationDigest())
                || !program.programDigest().equals(prepared.programDigest())
                || !original.contextDigest().equals(prepared.contextDigest())) throw invalid();
        NativeCalibrationTargetImages.ImagePair images = prepared.images();
        TargetBinding objective = program.targetBindings().get(0), storage = program.targetBindings().get(1);
        if (images == null || !images.objectiveFullTargetKnown() || !images.storageFullTargetKnown()
                || !objective.targetId().equals(images.objectiveTargetId()) || !storage.targetId().equals(images.storageTargetId())
                || !objective.expectedDigest().equals(images.objectiveSha256()) || !storage.expectedDigest().equals(images.storageSha256())
                || !ContractJson.sha256(images.objectiveBytes()).equals(images.objectiveSha256())
                || !ContractJson.sha256(images.storageBytes()).equals(images.storageSha256())
                || images.observedToTick() < images.observedFromTick()) throw invalid();
        control.checkpoint();
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
    private static List<String> commandInputs(ObjectNode program, String field, boolean allowEmpty) {
        JsonNode values = program.path(field);
        if (!values.isArray() || (!allowEmpty && values.isEmpty()) || values.size() > MAX_RECIPE_COMMANDS) throw invalid();
        var commands = new ArrayList<String>(values.size());
        for (JsonNode value : values) {
            if (!value.isTextual()) throw invalid();
            String command = value.textValue();
            if (command.isEmpty() || command.startsWith("#") || command.indexOf('\r') >= 0
                    || command.indexOf('\n') >= 0 || command.indexOf('\0') >= 0
                    || command.getBytes(StandardCharsets.UTF_8).length > MAX_COMMAND_BYTES) throw invalid();
            commands.add(command);
        }
        return List.copyOf(commands);
    }
    private static int commandIndex(ObjectNode program, String field) {
        JsonNode value = program.path(field);
        if (!value.isIntegralNumber() || !value.canConvertToInt() || value.intValue() < 0) throw invalid();
        return value.intValue();
    }
    private static String text(ObjectNode value, String key) { return HostDispatcher.string(value, key); }
    private static void sha(ObjectNode value, String key) { if (!text(value, key).matches("[a-f0-9]{64}")) throw invalid(); }
    private static ContractException invalid() { return new ContractException("CALIBRATION_APPROVAL_MISMATCH", "유한 calibration 승인이 원 route 또는 Invocation과 일치하지 않습니다"); }
    @Override public void close() { closed.set(true); accepted.values().forEach(value -> { value.cancellation.set(true); value.result.cancel(false); }); }
}
