package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.mojang.brigadier.ParseResults;
import com.mojang.brigadier.StringReader;
import io.github.daejunnom.mmmm.host.NativePlanApproval;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;

/** Read-only parser receipts. This boundary grants neither a target profile nor write approval. */
final class NativeTargetAdmission {
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int MAX_COMMAND_BYTES = 16 * 1024;
    private static final int MAX_ITEMS = 256;
    private static final int MAX_SOURCES = 64;
    private static final int MAX_SOURCE_BYTES = 64 * 1024;
    private static final Set<String> REQUEST_FIELDS = Set.of("kind", "instructions",
            "expectedRuntimeSourceFactsDigest", "expectedRegistryGeneration");
    private static final Set<String> STEP_FIELDS = Set.of("phase", "source_object_id", "source_node_id",
            "instance_id", "owner_prefab_id", "instruction", "encoded_commands", "commandDigest");
    private static final Set<String> OBSERVED_SOURCE_FIELDS = Set.of("className", "definitionSha256", "containerSha256",
            "sourceKind", "admissionEvidenceSha256", "loaderId", "generation");
    private static final Set<String> UNAVAILABLE_SOURCE_FIELDS = Set.of("className", "sourceKind", "reasonCode", "status");
    private final ContractJson contracts;

    NativeTargetAdmission(ContractJson contracts) { this.contracts = Objects.requireNonNull(contracts); }

    /**
     * Installed, private authority only: require current route, generation, complete parser/predicate
     * closure and Rust compiler provenance BEFORE any source factory, tree access or native parse.
     * Caller hashes, archive bytes, class resources and CodeSource do not implement this callback.
     */
    @FunctionalInterface
    interface SourceAdmission {
        SourceDecision require(ObjectNode installedContext, ObjectNode actualSourceFacts, String actualHostArtifactDigest,
                               String actualRegistryGeneration, ObjectNode sealedStep, int commandIndex);
    }

    /**
     * Checks closed native operation, actual parsed arguments, complete native context, current
     * source proof and the original per-step compiler provenance, without invoking a handler.
     * Returned receipts describe the actual selected parser/predicate and handler definitions.
     * A write guard requiring an Invocation cannot be used through a fabricated Invocation.
     */
    @FunctionalInterface
    interface ReadonlyParsedAdmission<S> {
        SourceReceipts require(ObjectNode installedContext, ObjectNode sealedStep, int commandIndex,
                               ParseResults<S> parsed, SourceDecision admittedBeforeParse);
    }

    /** Candidate source closure, authenticated by the installed SourceAdmission implementation. */
    record SourceDecision(boolean admitted, String reasonCode, ArrayNode parserSources, ArrayNode handlerSources) {
        SourceDecision { parserSources = copy(parserSources); handlerSources = copy(handlerSources); }
        @Override public ArrayNode parserSources() { return copy(parserSources); }
        @Override public ArrayNode handlerSources() { return copy(handlerSources); }
        static SourceDecision admitted(ArrayNode parsers, ArrayNode handlers) { return new SourceDecision(true, null, parsers, handlers); }
        static SourceDecision unsupported(String reason) { return new SourceDecision(false, reason, null, null); }
    }

    /** Actual parsed path selected by the mandatory read-only guard, not the whole candidate tree. */
    record SourceReceipts(ArrayNode parserSources, ArrayNode handlerSources) {
        SourceReceipts { parserSources = copy(parserSources); handlerSources = copy(handlerSources); }
        @Override public ArrayNode parserSources() { return copy(parserSources); }
        @Override public ArrayNode handlerSources() { return copy(handlerSources); }
    }

    /** Native source construction and dispatcher acquisition must remain inside this gated port. */
    @FunctionalInterface
    interface ParserAccess<S> { ParseResults<S> parse(String exactCommand); }

    ObjectNode inspect(MinecraftServer server, ServerPlayer pairedPlayer, ObjectNode installedContext,
                       ObjectNode actualSourceFacts, String actualHostArtifactDigest, String actualRegistryGeneration,
                       ObjectNode request, SourceAdmission admission, ReadonlyParsedAdmission<CommandSourceStack> guard) {
        Objects.requireNonNull(server); Objects.requireNonNull(pairedPlayer);
        if (!server.isSameThread()) throw failure("WRONG_THREAD");
        ObjectNode context = Objects.requireNonNull(installedContext).deepCopy();
        return observe(context, actualSourceFacts, actualHostArtifactDigest, actualRegistryGeneration, request,
                admission, command -> {
                    // SourceAdmission has already approved all code reachable from this factory.
                    if (server.getPlayerList().getPlayer(pairedPlayer.getUUID()) != pairedPlayer || pairedPlayer.isRemoved()) {
                        throw failure("EXECUTOR_DISCONNECTED");
                    }
                    ServerLevel level = level(server, text(context, "dimension"));
                    CommandSourceStack source = NativeCommands.source(pairedPlayer, level, context.deepCopy());
                    return server.getCommands().getDispatcher().parse(new StringReader(command), source);
                }, guard, () -> Integer.toUnsignedLong(server.getTickCount()), Clock.systemUTC());
    }

    /** Pure orchestration port used to test pre-parser rejection independently of Minecraft instances. */
    <S> ObjectNode observe(ObjectNode installedContext, ObjectNode actualSourceFacts, String actualHostArtifactDigest,
                           String actualRegistryGeneration, ObjectNode request, SourceAdmission admission,
                           ParserAccess<S> parser, ReadonlyParsedAdmission<S> guard, LongSupplier ticks, Clock clock) {
        ObjectNode context = Objects.requireNonNull(installedContext).deepCopy();
        ObjectNode facts = Objects.requireNonNull(actualSourceFacts).deepCopy();
        ObjectNode input = Objects.requireNonNull(request).deepCopy();
        contracts.validate("ExecutionContext", context);
        if (!ContractJson.contextDigest(context).equals(text(context, "contextDigest"))) throw failure("CONTEXT_CHANGED");
        digest(actualHostArtifactDigest); generation(actualRegistryGeneration);
        if (!context.path("environment").equals(facts.path("environment"))
                || !actualRegistryGeneration.equals(text(facts, "registryGeneration"))) throw failure("STALE_CONTEXT");
        List<ObjectNode> steps = steps(input);
        String actualFactsDigest = NativeProfileAdmission.sourceDigest(facts);
        boolean current = actualFactsDigest.equals(text(input, "expectedRuntimeSourceFactsDigest"))
                && actualRegistryGeneration.equals(text(input, "expectedRegistryGeneration"));
        long fromTick = tick(Objects.requireNonNull(ticks));
        ObjectNode result = ContractJson.newObject().put("protocolVersion", ContractJson.VERSION)
                .put("contextId", text(context, "contextId")).put("contextDigest", text(context, "contextDigest"))
                .put("runtimeSourceFactsDigest", actualFactsDigest).put("hostArtifactDigest", actualHostArtifactDigest)
                .put("registryGeneration", actualRegistryGeneration).put("observedFromTick", Long.toString(fromTick));
        result.set("environment", context.get("environment").deepCopy());
        ArrayNode results = result.putArray("instructions"); int responseBytes = 4096;
        for (ObjectNode step : steps) {
            ObjectNode item = ContractJson.newObject().put("stepDigest", ContractJson.digest(step));
            ArrayNode commands = item.putArray("commands"); results.add(item);
            int index = 0;
            for (JsonNode command : step.path("encoded_commands")) {
                String exactCommand = command.textValue();
                ObjectNode receipt = commandReceipt(exactCommand);
                if (!current) unsupported(receipt, "rejected", "TARGET_ADMISSION_STALE");
                else if (admission == null) unsupported(receipt, "unsupported", "PARSER_SOURCE_UNADMITTED");
                else if (guard == null || parser == null) unsupported(receipt, "unsupported", "NATIVE_READONLY_GUARD_UNAVAILABLE");
                else inspectCommand(context, facts, actualHostArtifactDigest, actualRegistryGeneration, step, index,
                        exactCommand, admission, parser, guard, receipt);
                responseBytes += ContractJson.bytes(receipt).length + 128;
                if (responseBytes > MAX_BYTES) throw failure("TARGET_ADMISSION_LIMIT");
                commands.add(receipt); index++;
            }
        }
        result.put("observedToTick", Long.toString(tick(ticks))).put("observedAt", Objects.requireNonNull(clock).instant().toString());
        if (ContractJson.bytes(result).length > MAX_BYTES) throw failure("TARGET_ADMISSION_LIMIT");
        return result;
    }

    private static <S> void inspectCommand(ObjectNode context, ObjectNode facts, String hostDigest, String generation,
                                           ObjectNode step, int index, String command, SourceAdmission admission,
                                           ParserAccess<S> parser, ReadonlyParsedAdmission<S> guard, ObjectNode receipt) {
        SourceDecision admitted;
        try {
            admitted = admission.require(context.deepCopy(), facts.deepCopy(), hostDigest, generation, step.deepCopy(), index);
            if (admitted == null) { unsupported(receipt, "unsupported", "PARSER_SOURCE_UNADMITTED"); return; }
            validateDecision(admitted, generation);
            if (!admitted.admitted()) {
                unsupported(receipt, "unsupported", admitted.reasonCode());
                setSources(receipt, admitted.parserSources(), admitted.handlerSources()); return;
            }
        } catch (RuntimeException exception) { unsupported(receipt, "unsupported", safeCode(exception, "PARSER_SOURCE_UNADMITTED")); return; }
        ParseResults<S> parsed;
        try {
            // No normalization, trimming, slash removal, escaping or domain/NBT regeneration.
            NativeSceneExecutor.requireOperationSignature(step.deepCopy(), index, command);
            parsed = Objects.requireNonNull(parser.parse(command));
        } catch (RuntimeException exception) { unsupported(receipt, "rejected", safeCode(exception, "NATIVE_PARSE_FAILED")); return; }
        if (!command.equals(parsed.getReader().getString())) { unsupported(receipt, "rejected", "NATIVE_PARSE_RESULT_INVALID"); return; }
        int consumed = parsed.getReader().getCursor();
        if (consumed < 0 || consumed > command.length()) { unsupported(receipt, "rejected", "NATIVE_PARSE_RESULT_INVALID"); return; }
        receipt.put("consumedUtf16", consumed);
        if (consumed != command.length() || parsed.getReader().canRead() || !parsed.getExceptions().isEmpty() || !executable(parsed)) {
            receipt.put("parseStatus", "rejected").put("reasonCode", "NATIVE_COMMAND_SYNTAX_INVALID"); return;
        }
        try {
            // A parser may have run before this drift check; preserve its actual consumed length.
            SourceDecision current = admission.require(context.deepCopy(), facts.deepCopy(), hostDigest, generation, step.deepCopy(), index);
            if (current == null) throw failure("PARSER_SOURCE_CHANGED");
            validateDecision(current, generation);
            if (!current.admitted() || !sameSources(admitted, current)) throw failure("PARSER_SOURCE_CHANGED");
            SourceReceipts actual = Objects.requireNonNull(guard.require(context.deepCopy(), step.deepCopy(), index, parsed, admitted));
            validateSources(actual.parserSources(), generation, true); validateSources(actual.handlerSources(), generation, true);
            subset(actual.parserSources(), admitted.parserSources()); subset(actual.handlerSources(), admitted.handlerSources());
            setSources(receipt, actual.parserSources(), actual.handlerSources());
            receipt.put("parseStatus", "parsed").putNull("reasonCode");
        } catch (RuntimeException exception) { receipt.put("parseStatus", "rejected").put("reasonCode", safeCode(exception, "NATIVE_READONLY_ADMISSION_FAILED")); }
    }

    private static ObjectNode commandReceipt(String command) {
        return ContractJson.newObject().put("commandDigest", ContractJson.digest(TextNode.valueOf(command)))
                .put("utf16Length", command.length()).putNull("consumedUtf16").put("parseStatus", "not_run")
                .putNull("reasonCode").putNull("parserSources").putNull("handlerSources");
    }
    private static void unsupported(ObjectNode value, String status, String reason) {
        code(reason); value.put("parseStatus", status).put("reasonCode", reason).putNull("consumedUtf16");
    }
    private static void setSources(ObjectNode value, ArrayNode parsers, ArrayNode handlers) {
        if (parsers == null) value.putNull("parserSources"); else value.set("parserSources", parsers.deepCopy());
        if (handlers == null) value.putNull("handlerSources"); else value.set("handlerSources", handlers.deepCopy());
    }
    private static void validateDecision(SourceDecision decision, String generation) {
        if (decision.admitted()) {
            if (decision.reasonCode() != null) throw failure("PARSER_SOURCE_RECEIPT_INVALID");
            validateSources(decision.parserSources(), generation, true); validateSources(decision.handlerSources(), generation, true);
        } else {
            code(decision.reasonCode()); validateSources(decision.parserSources(), generation, false); validateSources(decision.handlerSources(), generation, false);
        }
        ObjectNode bounded = ContractJson.newObject(); setSources(bounded, decision.parserSources(), decision.handlerSources());
        if (ContractJson.bytes(bounded).length > MAX_SOURCE_BYTES) throw failure("TARGET_ADMISSION_LIMIT");
    }
    private static void validateSources(ArrayNode sources, String generation, boolean observedRequired) {
        if (sources == null) { if (observedRequired) throw failure("PARSER_SOURCE_UNADMITTED"); return; }
        if (sources.isEmpty() || sources.size() > MAX_SOURCES) throw failure("PARSER_SOURCE_RECEIPT_INVALID");
        Set<String> classes = new HashSet<>();
        for (JsonNode node : sources) {
            ObjectNode source = ContractJson.object(node); String name = text(source, "className");
            if (name.length() > 512 || !name.matches("[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*") || !classes.add(name)
                    || !"loaded_definition_bytes".equals(text(source, "sourceKind"))) throw failure("PARSER_SOURCE_RECEIPT_INVALID");
            if (source.has("status")) {
                exact(source, UNAVAILABLE_SOURCE_FIELDS);
                if (observedRequired || !"unavailable".equals(text(source, "status"))) throw failure("PARSER_SOURCE_UNADMITTED");
                code(text(source, "reasonCode"));
            } else {
                exact(source, OBSERVED_SOURCE_FIELDS);
                for (String field : List.of("definitionSha256", "containerSha256", "admissionEvidenceSha256")) digest(text(source, field));
                if (!text(source, "loaderId").matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
                        || !generation.equals(text(source, "generation"))) throw failure("PARSER_SOURCE_UNADMITTED");
            }
        }
    }
    private static void subset(ArrayNode selected, ArrayNode admitted) {
        for (JsonNode source : selected) {
            boolean found = false; for (JsonNode candidate : admitted) found |= candidate.equals(source);
            if (!found) throw failure("PARSER_SOURCE_CHANGED");
        }
    }
    private static boolean sameSources(SourceDecision before, SourceDecision after) {
        return Objects.equals(before.parserSources(), after.parserSources()) && Objects.equals(before.handlerSources(), after.handlerSources());
    }
    private static <S> boolean executable(ParseResults<S> parsed) {
        var context = parsed.getContext(); int depth = 0;
        while (context.getChild() != null) { if (++depth > 32) throw failure("TARGET_ADMISSION_LIMIT"); context = context.getChild(); }
        return context.getCommand() != null;
    }

    private static List<ObjectNode> steps(ObjectNode request) {
        exact(request, REQUEST_FIELDS);
        if (!"target_admission".equals(text(request, "kind"))) throw invalid();
        digest(text(request, "expectedRuntimeSourceFactsDigest")); generation(text(request, "expectedRegistryGeneration"));
        if (ContractJson.bytes(request).length > MAX_BYTES) throw failure("TARGET_ADMISSION_LIMIT");
        ArrayNode instructions = array(request, "instructions", 1, MAX_ITEMS); int total = 0;
        List<ObjectNode> result = new ArrayList<>(); Set<String> unique = new HashSet<>();
        for (JsonNode value : instructions) {
            ObjectNode step = ContractJson.object(value).deepCopy(); exact(step, STEP_FIELDS);
            // Shared wire validation creates no plan membership or authority.
            NativePlanApproval.validateSealedNativeStep(step);
            ArrayNode commands = array(step, "encoded_commands", 1, 2);
            ObjectNode instruction = ContractJson.object(step.get("instruction"));
            int expected = text(instruction, "kind").startsWith("state_") && "scoreboard".equals(instruction.path("storage_kind").asText()) ? 2 : 1;
            if (commands.size() != expected || (total += commands.size()) > MAX_ITEMS) throw invalid();
            for (JsonNode command : commands) {
                if (!command.isTextual()) throw invalid(); String line = command.textValue();
                if (line.isEmpty() || line.startsWith("/") || line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0 || line.indexOf('\0') >= 0
                        || line.getBytes(StandardCharsets.UTF_8).length > MAX_COMMAND_BYTES) throw invalid();
                nestingBudget(line);
            }
            digest(text(step, "commandDigest"));
            if (!text(step, "commandDigest").equals(ContractJson.digest(commands))) throw failure("NATIVE_COMMAND_DIGEST_MISMATCH");
            if (!unique.add(ContractJson.digest(step))) throw invalid(); result.add(step);
        }
        return List.copyOf(result);
    }

    private static void nestingBudget(String command) {
        int depth = 0; char quote = 0; boolean escape = false;
        for (int index = 0; index < command.length(); index++) {
            char current = command.charAt(index);
            if (quote != 0) { if (escape) escape = false; else if (current == '\\') escape = true; else if (current == quote) quote = 0; }
            else if (current == '\'' || current == '"') quote = current;
            else if (current == '{' || current == '[') { if (++depth > 64) throw failure("TARGET_ADMISSION_LIMIT"); }
            else if ((current == '}' || current == ']') && depth > 0) depth--;
        }
    }
    private static ServerLevel level(MinecraftServer server, String dimension) {
        int count = 0; for (ServerLevel level : server.getAllLevels()) {
            if (++count > MAX_ITEMS) throw failure("TARGET_ADMISSION_LIMIT");
            if (level.dimension().identifier().toString().equals(dimension)) return level;
        }
        throw failure("DIMENSION_UNKNOWN");
    }
    private static long tick(LongSupplier ticks) { long value = ticks.getAsLong(); if (value < 0 || value > 0xffff_ffffL) throw failure("TARGET_ADMISSION_TICK_INVALID"); return value; }
    private static ArrayNode copy(ArrayNode value) { return value == null ? null : value.deepCopy(); }
    private static ArrayNode array(ObjectNode value, String field, int minimum, int maximum) { if (!(value.get(field) instanceof ArrayNode array) || array.size() < minimum || array.size() > maximum) throw invalid(); return array; }
    private static String text(ObjectNode value, String field) { if (!value.path(field).isTextual()) throw invalid(); return value.get(field).textValue(); }
    private static void digest(String value) { if (value == null || !value.matches("[a-f0-9]{64}")) throw invalid(); }
    private static void generation(String value) { if (value == null || !value.matches("(0|[1-9][0-9]{0,19})")) throw invalid(); }
    private static void code(String value) { if (value == null || !value.matches("[A-Z][A-Z0-9_]{0,127}")) throw failure("PARSER_SOURCE_RECEIPT_INVALID"); }
    private static void exact(ObjectNode value, Set<String> fields) { if (value.size() != fields.size()) throw invalid(); value.fieldNames().forEachRemaining(field -> { if (!fields.contains(field)) throw invalid(); }); }
    private static String safeCode(RuntimeException exception, String fallback) { String code = exception instanceof ContractException contract ? contract.code() : fallback; return code != null && code.matches("[A-Z][A-Z0-9_]{0,127}") ? code : fallback; }
    private static ContractException invalid() { return failure("TARGET_ADMISSION_INVALID"); }
    private static ContractException failure(String code) { return new ContractException(code, "Read-only target admission did not establish the required bounded native proof"); }
}
