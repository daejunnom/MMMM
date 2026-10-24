package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;

/** Historical immutable facts issued only by the actual completed native runner.
 * No JSON/fixture decoder, SourceAdmission, readback-CAS echo or execution grant. */
final class NativeCalibrationRunFacts {
    enum EventKind { ENTRY_BEGIN, HANDLER_RETURN, HANDLER_FAILURE, PRESEED_CAPTURE, QUEUE_RETURN, CUSTOM_RETURN, FRAME_RETURN }
    record Event(EventKind kind, int sequence, long tick, Integer executableRef, Integer returned,
                 String failureKind, String customKind, Integer quota, Boolean overflow, Integer queued, Integer newTop) { }
    record CommandFact(NativeCalibrationFunctions.SelectedStatement selected, Integer returned, List<Event> events) {
        CommandFact { events = List.copyOf(events); }
    }
    private final Invocation original;
    private final NativeCalibrationApproval.Program program;
    private final NativeCalibrationRunner.Pins pins;
    private final NativeCalibrationFunctions.SelectedFunction function;
    private final List<CommandFact> commands;
    private final NativeCalibrationTargetImages.ImagePair preseed, after;
    private final long from, to;
    private final String observedAt;
    private final NativeCommandDispatch.Observation callbacks;
    private final byte[] frozen;
    private final long retainedBytes;
    private NativeCalibrationRunFacts(NativeCalibrationRunner.CompletedRun actual, NativeCalibrationApproval.Control control) {
        original = actual.original(); program = actual.program(); pins = actual.pins(); function = actual.function();
        commands = List.copyOf(actual.commands()); preseed = actual.preseed(); after = actual.after();
        from = actual.from(); to = actual.to(); observedAt = actual.observedAt(); callbacks = actual.callbacks();
        frozen = ContractJson.bytes(render(control::checkpoint));
        long charge = frozen.length + function.executables().retainedPayloadBytes() + 2L * function.loadedFunction().bytes().length
                + preseed.objectiveBytes().length + preseed.storageBytes().length + after.objectiveBytes().length + after.storageBytes().length
                + 1024L + callbacks.callbackCount() * 24L;
        for (CommandFact command : commands)
            charge += 128L + 2L * command.selected().originalInput().length() + 16L * command.selected().executableRefs().size() + 96L * command.events().size();
        retainedBytes = charge;
    }
    static NativeCalibrationRunFacts completed(NativeCalibrationRunner.CompletedRun actual, NativeCalibrationApproval.Control control) {
        return new NativeCalibrationRunFacts(actual, control);
    }
    /** Explicit byte copies plus conservative collection/reference charge, not a JVM heap measurement. */
    long retainedBytes() { return retainedBytes; }
    String invocationDigest() { return ContractJson.digest(original.wire()); }
    NativeCommandDispatch.Observation callbacks() { return callbacks; }
    void checkCurrent(Invocation actual, NativeCalibrationApproval.Control control) {
        NativeCalibrationFunctions.checked(() -> {
            if (!invocationDigest().equals(ContractJson.digest(actual.wire()))) throw stale();
            function.checkCurrent(control); function.reobserveSourceBytes(control); return null;
        }, control);
    }
    ObjectNode wire(NativeCalibrationApproval.Control control) {
        return wire(control::checkpoint);
    }
    ObjectNode wire(Runnable checkpoint) {
        return NativeCalibrationFunctions.checked(() -> ContractJson.object(ContractJson.parse(frozen)), checkpoint);
    }
    private ObjectNode render(Runnable checkpoint) {
        return NativeCalibrationFunctions.checked(() -> {
            ObjectNode value = metadata(original, program, pins, function, checkpoint).put("format", NativeCalibrationSource.FORMAT)
                    .put("observedFromTick", Long.toString(from)).put("observedToTick", Long.toString(to)).put("observedAt", observedAt);
            ArrayNode encoded = (ArrayNode) value.get("commands");
            for (int ordinal = 0; ordinal < commands.size(); ordinal++) {
                checkpoint.run(); CommandFact fact = commands.get(ordinal); ObjectNode command = (ObjectNode) encoded.get(ordinal);
                if (fact.returned() == null) command.putNull("nativeReturn"); else command.put("nativeReturn", fact.returned());
                ArrayNode events = command.putArray("events");
                for (Event event : fact.events()) { checkpoint.run(); events.add(event(event)); }
                bounded(value);
            }
            value.set("preseedState", images(preseed)); value.set("afterState", images(after)); bounded(value); return value;
        }, checkpoint);
    }
    /** Exact already-observed metadata is checked before intent/effects. No run,
     * events or future images are manufactured or returned by this capacity check. */
    static void requireMetadataFits(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationRunner.Pins pins,
            NativeCalibrationFunctions.SelectedFunction function, NativeCalibrationTargetImages.ImagePair before,
            NativeCalibrationApproval.Control control) {
        NativeCalibrationFunctions.checked(() -> {
            ObjectNode metadata = metadata(original, program, pins, function, control::checkpoint);
            // Required future entry events, one preseed/queue event, four completion
            // fields and the two image wrappers. Runtime-dependent extra events and
            // changed images are checked again on the actual completed record.
            int nodes = 4 * function.statements().size() + 40;
            long bytes = 8192L + 4L * (before.objectiveBytes().length + before.storageBytes().length);
            bounded(metadata, nodes, bytes); return null;
        }, control);
    }
    /** Partial metadata only, not a source/3 envelope or an issuance factory. */
    private static ObjectNode metadata(Invocation original, NativeCalibrationApproval.Program program, NativeCalibrationRunner.Pins pins,
            NativeCalibrationFunctions.SelectedFunction function, Runnable checkpoint) {
            var loaded = function.loadedFunction();
            ObjectNode value = pins.envelope(original.context())
                    .put("invocationId", original.invocationId()).put("invocationDigest", ContractJson.digest(original.wire()))
                    .put("programDigest", program.programDigest()).put("functionId", loaded.functionId().toString())
                    .put("sourceResourceId", loaded.resourceId().toString()).put("sourcePackId", loaded.sourcePackId())
                    .put("sourceRawSha256", loaded.sha256()).put("commandsDigest", commandsDigest(program.commands()))
                    .put("preseedEndIndex", program.preseedEndIndex()).put("commandStageIndex", program.selectedCommandStageIndex());
            var views = function.executables().executableViews(); var indexes = new IdentityHashMap<Class<?>, Integer>();
            ArrayNode encodedViews = value.putArray("executableViews");
            for (int index = 0; index < views.size(); index++) {
                checkpoint.run(); var view = views.get(index); indexes.put(view.actualClass(), index);
                encodedViews.add(ContractJson.newObject().put("sourceKind", "current_vm_executable")
                        .put("nativeEnvelopeHex", envelopeHex(view.observation().envelope())));
                bounded(value);
            }
            ArrayNode encoded = value.putArray("commands");
            for (int ordinal = 0; ordinal < function.statements().size(); ordinal++) {
                checkpoint.run(); var selected = function.statements().get(ordinal);
                ObjectNode command = ContractJson.newObject().put("ordinal", ordinal)
                        .put("commandDigest", ContractJson.digest(TextNode.valueOf(selected.originalInput())))
                        .put("chainInputDigest", ContractJson.digest(TextNode.valueOf(selected.originalInput())))
                        .put("consumedUtf16", selected.rangeEnd()).put("rangeStartUtf16", selected.rangeStart())
                        .put("rangeEndUtf16", selected.rangeEnd());
                command.putNull("nativeReturn");
                ArrayNode methods = command.putArray("executables");
                for (int ref : selected.executableRefs()) {
                    checkpoint.run(); var method = function.executables().facts().get(ref);
                    ObjectNode executable = ContractJson.newObject().put("role", method.role().name().toLowerCase(java.util.Locale.ROOT))
                            .put("receiverViewRef", viewRef(indexes, method.actualReceiver().getClass()));
                    executable.set("selectedMethod", method(method.selectedMethod(), null));
                    executable.set("implementation", method(method.implementation(), viewRef(indexes, method.implementation().getDeclaringClass())));
                    if (method.hiddenStaticTarget() == null) executable.putNull("hiddenTarget");
                    else executable.set("hiddenTarget", method(method.hiddenStaticTarget(), viewRef(indexes, method.hiddenStaticTarget().getDeclaringClass()))
                            .put("forwarderEnvelopeHex", envelopeHex(method.hiddenForwarderEnvelope())));
                    methods.add(executable);
                }
                command.putArray("events");
                encoded.add(command); bounded(value);
            }
            return value;
    }
    static String commandsDigest(List<String> commands) {
        ArrayNode values = ContractJson.newObject().putArray("commands"); commands.forEach(values::add); return ContractJson.digest(values);
    }
    static ObjectNode fullImages(NativeCalibrationRunner.Pins pins, ObjectNode context, NativeCalibrationTargetImages.ImagePair actual) {
        ObjectNode value = pins.envelope(context).put("format", "mmmm.native.calibration-target-images/1");
        ObjectNode pair = images(actual); value.set("targets", pair.get("targets"));
        value.set("observedFromTick", pair.get("observedFromTick")); value.set("observedToTick", pair.get("observedToTick"));
        value.put("observedAt", Instant.now().toString()); bounded(value); return value;
    }
    static ObjectNode images(NativeCalibrationTargetImages.ImagePair actual) {
        ObjectNode value = ContractJson.newObject().put("observedFromTick", Long.toString(actual.observedFromTick()))
                .put("observedToTick", Long.toString(actual.observedToTick()));
        value.putArray("targets").add(target(actual.objectiveTargetId(), actual.objectiveBytes(), actual.objectiveSha256()))
                .add(target(actual.storageTargetId(), actual.storageBytes(), actual.storageSha256())); return value;
    }
    private static ObjectNode target(String id, byte[] bytes, String sha) {
        if (!ContractJson.sha256(bytes).equals(sha)) throw stale();
        return ContractJson.newObject().put("targetId", id).put("rawBytesHex", HexFormat.of().formatHex(bytes)).put("rawSha256", sha);
    }
    private static ObjectNode method(Method method, Integer ref) {
        ObjectNode value = ContractJson.newObject().put("name", method.getName())
                .put("descriptor", MethodType.methodType(method.getReturnType(), method.getParameterTypes()).toMethodDescriptorString());
        if (ref != null) value.put("viewRef", ref); return value;
    }
    private static String envelopeHex(byte[] actual) {
        if (actual.length > 512 * 1024) throw limit();
        return HexFormat.of().formatHex(actual);
    }
    private static int viewRef(IdentityHashMap<Class<?>, Integer> views, Class<?> actual) {
        Integer result = views.get(actual); if (result == null) throw stale(); return result;
    }
    private static ObjectNode event(Event event) {
        ObjectNode value = ContractJson.newObject().put("kind", event.kind().name().toLowerCase(java.util.Locale.ROOT))
                .put("sequence", event.sequence()).put("tick", Long.toString(event.tick()));
        switch (event.kind()) {
            case HANDLER_RETURN -> value.put("executableRef", event.executableRef()).put("returned", event.returned());
            case HANDLER_FAILURE -> value.put("executableRef", event.executableRef()).put("failureKind", event.failureKind());
            case CUSTOM_RETURN -> value.put("executableRef", event.executableRef()).put("customKind", event.customKind());
            case FRAME_RETURN -> { if (event.returned() == null) value.putNull("returned"); else value.put("returned", event.returned()); }
            case QUEUE_RETURN -> value.put("commandQuota", event.quota()).put("queueOverflow", event.overflow())
                    .put("queued", event.queued()).put("newTopCommands", event.newTop());
            default -> { }
        }
        return value;
    }
    static void bounded(ObjectNode value) {
        bounded(value, 0, 0);
    }
    private static void bounded(ObjectNode value, int reservedNodes, long reservedBytes) {
        // Exact fixed RPC/HostResponse structure, with maximum-length request IDs
        // and eventSequence. No external path, profile or new protocol is introduced.
        ObjectNode response = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION).put("requestId", "r".repeat(128))
                .put("eventSequence", "18446744073709551615").put("status", "ok"); response.set("payload", value);
        ObjectNode rpc = ContractJson.newObject().put("jsonrpc", "2.0").put("id", "r".repeat(128)); rpc.set("result", response);
        int[] count = {reservedNodes}; count(rpc, 0, count);
        try { if (ContractJson.bytes(rpc).length + reservedBytes > 1024L * 1024) throw limit(); }
        catch (ContractException original) {
            if ("CALIBRATION_RUN_SOURCE_LIMIT".equals(original.code())) throw original;
            ContractException failure = limit(); failure.initCause(original); throw failure;
        }
    }
    private static void count(com.fasterxml.jackson.databind.JsonNode value, int depth, int[] nodes) {
        if (++nodes[0] > 4096 || depth > 64) throw limit();
        if (value.isContainerNode()) for (var child : value) count(child, depth + 1, nodes);
    }
    private static ContractException limit() { return new ContractException("CALIBRATION_RUN_SOURCE_LIMIT", "Actual facts exceed the original complete RPC frame bound"); }
    private static ContractException stale() { return new ContractException("CALIBRATION_RUN_SOURCE_STALE", "Original native run facts differ from the current retained source"); }
}
