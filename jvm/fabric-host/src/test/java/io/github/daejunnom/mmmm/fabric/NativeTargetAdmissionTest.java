package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.StringReader;
import com.mojang.brigadier.arguments.ArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.builder.RequiredArgumentBuilder;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import com.mojang.brigadier.suggestion.Suggestions;
import com.mojang.brigadier.suggestion.SuggestionsBuilder;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure parser-boundary fixtures; invented proof bytes here are never native/runtime evidence.
 * Original examples do not cover rejected source admission before custom Brigadier callbacks.
 */
final class NativeTargetAdmissionTest {
    private static final String HOST = "a".repeat(64);
    private static final String GENERATION = "31";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-14T00:00:00Z"), ZoneOffset.UTC);
    private static final String COMMAND = "execute in minecraft:overworld run data merge block 0 64 0 {Command:\"say 😀\",auto:0b,TrackOutput:0b}";
    private final NativeTargetAdmission admission = new NativeTargetAdmission(new ContractJson());

    @Test void missingDeniedUnavailableAndMalformedProofNeverStartSourceOrBrigadierCallbacks() throws IOException {
        for (int kind = 0; kind < 7; kind++) {
            Harness harness = new Harness(); Inputs inputs = inputs();
            NativeTargetAdmission.SourceAdmission source = switch (kind) {
                case 0 -> null;
                case 1 -> (context, facts, host, generation, step, index) -> NativeTargetAdmission.SourceDecision.unsupported("PARSER_SOURCE_UNADMITTED");
                case 2 -> (context, facts, host, generation, step, index) -> null;
                case 3 -> (context, facts, host, generation, step, index) -> NativeTargetAdmission.SourceDecision.admitted(null, null);
                case 4 -> (context, facts, host, generation, step, index) -> {
                    ArrayNode unknown = sources("fixture.Parser", GENERATION); first(unknown).remove("definitionSha256");
                    return NativeTargetAdmission.SourceDecision.admitted(unknown, sources("fixture.Handler", GENERATION));
                };
                case 5 -> (context, facts, host, generation, step, index) -> {
                    ObjectNode unavailable = ContractJson.newObject().put("className", "fixture.Parser").put("sourceKind", "loaded_definition_bytes")
                            .put("reasonCode", "DEFINITION_UNAVAILABLE").put("status", "unavailable");
                    ArrayNode parsers = ContractJson.newObject().putArray("sources"); parsers.add(unavailable);
                    return new NativeTargetAdmission.SourceDecision(false, "DEFINITION_UNAVAILABLE", parsers, null);
                };
                default -> (context, facts, host, generation, step, index) -> {
                    ArrayNode parsers = sources("fixture.Parser", GENERATION);
                    for (int number = 0; number < 64; number++) parsers.add(first(parsers).deepCopy().put("className", "fixture.Parser" + number));
                    return NativeTargetAdmission.SourceDecision.admitted(parsers, sources("fixture.Handler", GENERATION));
                };
            };
            ObjectNode response = observe(inputs, harness, source, acceptedGuard());
            ObjectNode command = receipt(response, 0);
            assertEquals("unsupported", command.path("parseStatus").asText()); assertTrue(command.path("consumedUtf16").isNull());
            if (kind != 5) { assertTrue(command.path("parserSources").isNull()); assertTrue(command.path("handlerSources").isNull()); }
            else { assertEquals("unavailable", command.path("parserSources").get(0).path("status").asText()); assertTrue(command.path("handlerSources").isNull()); }
            harness.assertUntouched();
        }
    }

    @Test void stalePinsAndMissingReadonlyGuardCannotBorrowAnOtherwiseAcceptedSourceGate() throws IOException {
        for (String field : Set.of("expectedRuntimeSourceFactsDigest", "expectedRegistryGeneration")) {
            Harness harness = new Harness(); Inputs inputs = inputs();
            inputs.request().put(field, field.equals("expectedRegistryGeneration") ? "32" : "b".repeat(64));
            AtomicInteger gates = new AtomicInteger();
            ObjectNode response = observe(inputs, harness, (context, facts, host, generation, step, index) -> { gates.incrementAndGet(); return accepted(); }, acceptedGuard());
            assertEquals("rejected", receipt(response, 0).path("parseStatus").asText()); assertEquals(0, gates.get()); harness.assertUntouched();
        }
        Harness harness = new Harness(); Inputs inputs = inputs();
        assertEquals("NATIVE_READONLY_GUARD_UNAVAILABLE", receipt(observe(inputs, harness, acceptedSource(), null), 0).path("reasonCode").asText());
        harness.assertUntouched();
    }

    @Test void closedRequestDigestLineAndNestingLimitsRejectBeforeSourceFactory() throws IOException {
        for (int kind = 0; kind < 7; kind++) {
            Inputs inputs = inputs(); Harness harness = new Harness(); ObjectNode step = first(inputs.request().withArray("instructions"));
            switch (kind) {
                case 0 -> inputs.request().put("callerVerified", true);
                case 1 -> step.put("commandDigest", "b".repeat(64));
                case 2 -> command(step, "/" + COMMAND);
                case 3 -> command(step, COMMAND + "\n");
                case 4 -> command(step, "x".repeat(16 * 1024 + 1));
                case 5 -> command(step, "execute " + "[".repeat(65) + "0" + "]".repeat(65));
                default -> {
                    step.putArray("encoded_commands").add(COMMAND + String.valueOf((char) 0xd800));
                    step.put("commandDigest", "b".repeat(64)); // Invalid UTF-16 must be rejected before digest calculation or parser entry.
                }
            }
            assertThrows(ContractException.class, () -> observe(inputs, harness, acceptedSource(), acceptedGuard())); harness.assertUntouched();
        }
    }

    @Test void acceptedControlParsesExactUnicodeTextButNeverExecutesHandlerOrSuggestions() throws IOException {
        Inputs inputs = inputs(); Harness harness = new Harness(); String before = inputs.request().toString();
        ObjectNode response = observe(inputs, harness, acceptedSource(), acceptedGuard()); ObjectNode receipt = receipt(response, 0);
        assertEquals("parsed", receipt.path("parseStatus").asText()); assertTrue(receipt.path("reasonCode").isNull());
        assertEquals(COMMAND.length(), receipt.path("utf16Length").intValue()); assertEquals(COMMAND.length(), receipt.path("consumedUtf16").intValue());
        assertEquals(COMMAND, harness.lastCommand); assertEquals(1, harness.sourceFactory.get()); assertEquals(1, harness.argument.get());
        assertTrue(harness.requirement.get() > 0); assertEquals(0, harness.handler.get()); assertEquals(0, harness.suggestion.get());
        assertEquals(ContractJson.digest(TextNode.valueOf(COMMAND)), receipt.path("commandDigest").asText());
        assertEquals(ContractJson.digest(inputs.request().path("instructions").get(0)), response.path("instructions").get(0).path("stepDigest").asText());
        assertEquals(before, inputs.request().toString()); assertEquals(11, response.size()); assertEquals(7, receipt.size());
        assertEquals("31", response.path("registryGeneration").asText()); assertEquals("7", response.path("observedFromTick").asText());
        assertEquals("2026-10-14T00:00:00Z", response.path("observedAt").asText()); assertFalse(response.has("verified"));
    }

    @Test void incompleteParseOrWrongOriginalReaderCannotBecomeFullConsumption() throws IOException {
        Inputs inputs = inputs(); Harness harness = new Harness(); harness.partial = true;
        ObjectNode result = observe(inputs, harness, acceptedSource(), acceptedGuard());
        assertEquals("rejected", receipt(result, 0).path("parseStatus").asText()); assertTrue(receipt(result, 0).path("consumedUtf16").intValue() < COMMAND.length());
        Harness wrongReader = new Harness();
        ObjectNode wrong = admission.observe(inputs.context(), inputs.facts(), HOST, GENERATION, inputs.request(), acceptedSource(),
                line -> wrongReader.parse("execute another command"), acceptedGuard(), () -> 7L, CLOCK);
        assertEquals("NATIVE_PARSE_RESULT_INVALID", receipt(wrong, 0).path("reasonCode").asText()); assertTrue(receipt(wrong, 0).path("consumedUtf16").isNull());
    }

    @Test void sourceDriftAfterParseRetainsActualConsumptionAndBlocksNextCommand() throws IOException {
        Inputs inputs = inputs(); ObjectNode second = first(inputs.request().withArray("instructions")).deepCopy().put("instance_id", "instance-second");
        inputs.request().withArray("instructions").add(second); Harness harness = new Harness(); AtomicInteger calls = new AtomicInteger();
        ObjectNode result = observe(inputs, harness, (context, facts, host, generation, step, index) -> calls.incrementAndGet() == 1
                ? accepted() : NativeTargetAdmission.SourceDecision.unsupported("PARSER_SOURCE_CHANGED"), acceptedGuard());
        ObjectNode first = receipt(result, 0); ObjectNode next = receipt(result, 1);
        assertEquals("rejected", first.path("parseStatus").asText()); assertEquals(COMMAND.length(), first.path("consumedUtf16").intValue());
        assertEquals("unsupported", next.path("parseStatus").asText()); assertTrue(next.path("consumedUtf16").isNull());
        assertEquals(1, harness.sourceFactory.get()); assertEquals(1, harness.argument.get()); assertEquals(0, harness.handler.get());
    }

    @Test void oldGenerationOrUnadmittedActualPathReceiptsCannotAuthorizeParsedResult() throws IOException {
        Inputs inputs = inputs(); Harness stale = new Harness();
        ObjectNode notStarted = observe(inputs, stale, (context, facts, host, generation, step, index) -> NativeTargetAdmission.SourceDecision.admitted(
                sources("fixture.Parser", "30"), sources("fixture.Handler", "30")), acceptedGuard());
        assertEquals("unsupported", receipt(notStarted, 0).path("parseStatus").asText()); stale.assertUntouched();
        Harness changed = new Harness(); ObjectNode rejected = observe(inputs, changed, acceptedSource(),
                (context, step, index, parsed, admitted) -> new NativeTargetAdmission.SourceReceipts(sources("fixture.OtherParser", GENERATION), sources("fixture.Handler", GENERATION)));
        assertEquals("rejected", receipt(rejected, 0).path("parseStatus").asText()); assertEquals("PARSER_SOURCE_CHANGED", receipt(rejected, 0).path("reasonCode").asText());
        assertTrue(receipt(rejected, 0).path("parserSources").isNull()); assertEquals(0, changed.handler.get());
    }

    @Test void callbackArgumentsAndSourceArraysAreDefensiveSnapshots() throws IOException {
        Inputs inputs = inputs(); String contextBefore = inputs.context().toString(); String factsBefore = inputs.facts().toString();
        ArrayNode parsers = sources("fixture.Parser", GENERATION); NativeTargetAdmission.SourceDecision decision = NativeTargetAdmission.SourceDecision.admitted(parsers, sources("fixture.Handler", GENERATION));
        first(parsers).put("generation", "other"); first(decision.parserSources()).put("generation", "other");
        ObjectNode result = observe(inputs, new Harness(), (context, facts, host, generation, step, index) -> {
            context.put("contextDigest", "c".repeat(64)); facts.put("registryGeneration", "100"); step.put("source_object_id", "changed"); return decision;
        }, acceptedGuard());
        assertEquals("parsed", receipt(result, 0).path("parseStatus").asText()); assertEquals(contextBefore, inputs.context().toString()); assertEquals(factsBefore, inputs.facts().toString());
    }

    private ObjectNode observe(Inputs inputs, Harness harness, NativeTargetAdmission.SourceAdmission source,
                               NativeTargetAdmission.ReadonlyParsedAdmission<Object> guard) {
        return admission.observe(inputs.context(), inputs.facts(), HOST, GENERATION, inputs.request(), source, harness::parse, guard, () -> 7L, CLOCK);
    }
    private static NativeTargetAdmission.SourceAdmission acceptedSource() { return (context, facts, host, generation, step, index) -> accepted(); }
    private static NativeTargetAdmission.SourceDecision accepted() { return NativeTargetAdmission.SourceDecision.admitted(sources("fixture.Parser", GENERATION), sources("fixture.Handler", GENERATION)); }
    private static NativeTargetAdmission.ReadonlyParsedAdmission<Object> acceptedGuard() { return (context, step, index, parsed, admitted) -> new NativeTargetAdmission.SourceReceipts(admitted.parserSources(), admitted.handlerSources()); }
    private static ArrayNode sources(String name, String generation) {
        ArrayNode sources = ContractJson.newObject().putArray("sources");
        sources.add(ContractJson.newObject().put("className", name).put("definitionSha256", "b".repeat(64)).put("containerSha256", "c".repeat(64))
                .put("sourceKind", "loaded_definition_bytes").put("admissionEvidenceSha256", "d".repeat(64)).put("loaderId", "fixture-loader").put("generation", generation));
        return sources;
    }
    private record Inputs(ObjectNode context, ObjectNode facts, ObjectNode request) { }
    private static Inputs inputs() throws IOException {
        Path source = Path.of("examples", "execution-context.json");
        if (!Files.isRegularFile(source)) source = Path.of("..", "..", "examples", "execution-context.json");
        ObjectNode context = ContractJson.object(ContractJson.parse(Files.readAllBytes(source)));
        ObjectNode facts = ContractJson.newObject().put("registryGeneration", GENERATION).put("observedAt", "2026-10-14T00:00:00Z"); facts.set("environment", context.get("environment").deepCopy());
        ObjectNode instruction = ContractJson.newObject().put("kind", "command_data").put("dimension", "minecraft:overworld").put("source", "say 😀");
        instruction.putArray("position").add(0).add(64).add(0);
        ObjectNode step = ContractJson.newObject().put("phase", "stage").put("source_object_id", "object-fixture").putNull("source_node_id")
                .put("instance_id", "instance-fixture").put("owner_prefab_id", "prefab-fixture"); step.set("instruction", instruction); command(step, COMMAND);
        ObjectNode request = ContractJson.newObject().put("kind", "target_admission").put("expectedRuntimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(facts)).put("expectedRegistryGeneration", GENERATION);
        request.putArray("instructions").add(step); return new Inputs(context, facts, request);
    }
    private static void command(ObjectNode step, String command) { ArrayNode commands = step.putArray("encoded_commands").add(command); step.put("commandDigest", ContractJson.digest(commands)); }
    private static ObjectNode first(ArrayNode values) { return ContractJson.object(values.get(0)); }
    private static ObjectNode receipt(ObjectNode response, int step) { return ContractJson.object(response.path("instructions").get(step).path("commands").get(0)); }

    private static final class Harness {
        final AtomicInteger sourceFactory = new AtomicInteger(); final AtomicInteger requirement = new AtomicInteger();
        final AtomicInteger argument = new AtomicInteger(); final AtomicInteger handler = new AtomicInteger(); final AtomicInteger suggestion = new AtomicInteger();
        final CommandDispatcher<Object> dispatcher = new CommandDispatcher<>(); boolean partial; String lastCommand;
        Harness() {
            ArgumentType<String> type = new ArgumentType<>() {
                @Override public String parse(StringReader reader) throws CommandSyntaxException {
                    argument.incrementAndGet(); String value = reader.getRemaining(); reader.setCursor(partial ? reader.getCursor() + 1 : reader.getTotalLength()); return value;
                }
                @Override public <S> CompletableFuture<Suggestions> listSuggestions(CommandContext<S> context, SuggestionsBuilder builder) {
                    suggestion.incrementAndGet(); return builder.suggest("fixture").buildFuture();
                }
            };
            dispatcher.register(LiteralArgumentBuilder.<Object>literal("execute").requires(source -> { requirement.incrementAndGet(); return true; })
                    .then(RequiredArgumentBuilder.<Object, String>argument("body", type).executes(context -> { handler.incrementAndGet(); return 1; })));
        }
        com.mojang.brigadier.ParseResults<Object> parse(String command) { sourceFactory.incrementAndGet(); lastCommand = command; return dispatcher.parse(new StringReader(command), new Object()); }
        void assertUntouched() { assertEquals(0, sourceFactory.get()); assertEquals(0, requirement.get()); assertEquals(0, argument.get()); assertEquals(0, handler.get()); assertEquals(0, suggestion.get()); }
    }
}
