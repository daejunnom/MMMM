package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import net.minecraft.core.BlockPos;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Small direct-observer orchestration fixtures, never native permission or live-game evidence.
 * Existing parser/profile fixtures cannot represent ordered 27-cell reads or discard partial cells.
 */
final class OwnedBlockPatchPreflightTest {
    private static final String HOST = "a".repeat(64);
    private static final String IMPL = "b".repeat(64);
    private static final String GENERATION = "31";
    private static final Set<String> RECEIPT_FIELDS = Set.of("format", "status", "reasonCode", "producerId", "hostArtifactDigest",
            "implementationDigest", "profileDigest", "runtimeSourceFactsDigest", "registryGeneration", "contextDigest", "dimension",
            "position", "expectedState", "desiredState", "observedFromTick", "observedToTick", "cells", "conditionsDigest",
            "directCoverage", "indirectEffects", "exactUndoSupported", "lossCode", "limitations");

    @Test void directReceiptBindsAllTwentySevenOrderedCellsAndExplicitlyExcludesIndirectUndo() {
        ObjectNode context = context(), input = input(); List<BlockPos> visited = new ArrayList<>();
        ObjectNode receipt = observe(context, input, position -> { visited.add(position); return air(); }, () -> { });
        assertEquals("known", receipt.path("status").asText()); assertTrue(receipt.path("reasonCode").isNull());
        Set<String> fields = new java.util.HashSet<>(); receipt.fieldNames().forEachRemaining(fields::add); assertEquals(RECEIPT_FIELDS, fields);
        assertEquals(27, visited.size()); assertEquals(27, receipt.path("cells").size());
        assertEquals(new BlockPos(-1, 63, -1), visited.getFirst()); assertEquals(new BlockPos(0, 64, 0), visited.get(13));
        assertEquals(new BlockPos(1, 65, 1), visited.getLast());
        assertEquals(OwnedBlockPatchPreflight.PRODUCER, receipt.path("producerId").asText());
        assertEquals("block_state_cells", receipt.path("directCoverage").asText()); assertEquals("not_observed", receipt.path("indirectEffects").asText());
        assertFalse(receipt.path("exactUndoSupported").booleanValue()); assertEquals(OwnedBlockPatchPreflight.LOSS, receipt.path("lossCode").asText());
        List<String> limitations = new ArrayList<>(); receipt.path("limitations").forEach(value -> limitations.add(value.textValue()));
        assertEquals(OwnedBlockPatchPreflight.LIMITATIONS, limitations);
        assertEquals(ContractJson.digest(OwnedBlockPatchPreflight.profile(HOST, IMPL)), receipt.path("profileDigest").asText());
        String pin = receipt.path("conditionsDigest").asText(); assertEquals(pin, OwnedBlockPatchPreflight.conditionsDigest(receipt));
        ObjectNode changed = receipt.deepCopy().put("observedFromTick", "99").put("observedToTick", "100");
        assertEquals(pin, OwnedBlockPatchPreflight.conditionsDigest(changed));
        changed.put("exactUndoSupported", true); assertNotEquals(pin, OwnedBlockPatchPreflight.conditionsDigest(changed));
        assertEquals("minecraft:stone", receipt.path("desiredState").path("blockId").asText());
        assertEquals("minecraft:air", receipt.path("cells").get(13).path("state").path("blockId").asText());
    }

    @Test void unsupportedCellConditionsNeverPublishAPartialFootprint() {
        List<String> reasons = List.of("OWNED_BLOCK_STATE_UNSUPPORTED", "OWNED_BLOCK_ENTITY_PRESENT", "OWNED_BLOCK_FLUID_PRESENT",
                "OWNED_BLOCK_EXPECTED_STATE_CHANGED", "OWNED_BLOCK_NEIGHBOR_NOT_AIR");
        for (int kind = 0; kind < reasons.size(); kind++) {
            final int selected = kind; AtomicInteger reads = new AtomicInteger();
            ObjectNode receipt = observe(context(), input(), position -> {
                reads.incrementAndGet(); boolean center = position.equals(new BlockPos(0, 64, 0));
                if (selected == 0 && center) return new OwnedBlockPatchPreflight.Cell(state("minecraft:dirt"), null, true, true);
                if (selected == 1 && center) return new OwnedBlockPatchPreflight.Cell(state("minecraft:air"), "vanilla_air", false, true);
                if (selected == 2 && center) return new OwnedBlockPatchPreflight.Cell(state("minecraft:air"), "vanilla_air", true, false);
                if (selected == 3 && center || selected == 4 && reads.get() == 15) return new OwnedBlockPatchPreflight.Cell(state("minecraft:stone"), "vanilla_stone", true, true);
                return air();
            }, () -> { });
            assertEquals("unsupported", receipt.path("status").asText()); assertEquals(reasons.get(kind), receipt.path("reasonCode").asText());
            assertTrue(reads.get() > 1); assertTrue(receipt.path("cells").isEmpty()); assertTrue(receipt.path("conditionsDigest").isNull());
        }
    }

    @Test void CallerFlagsAndStaleIdentityFailBeforeAnyCellRead() {
        for (int kind = 0; kind < 4; kind++) {
            ObjectNode input = input(), context = context(); AtomicInteger reads = new AtomicInteger();
            switch (kind) {
                case 0 -> input.put("callerApproved", true);
                case 1 -> input.put("expectedRegistryGeneration", "32");
                case 2 -> input.put("dimension", "minecraft:the_nether");
                default -> input.put("expectedRegistryGeneration", "031");
            }
            assertThrows(ContractException.class, () -> observe(context, input, position -> { reads.incrementAndGet(); return air(); }, () -> { }));
            assertEquals(0, reads.get());
        }
        ObjectNode unsupported = input(); unsupported.withObject("desiredState").put("blockId", "minecraft:dirt");
        AtomicInteger reads = new AtomicInteger(); ObjectNode receipt = observe(context(), unsupported, position -> { reads.incrementAndGet(); return air(); }, () -> { });
        assertEquals("OWNED_BLOCK_STATE_UNSUPPORTED", receipt.path("reasonCode").asText()); assertEquals(0, reads.get());
    }

    @Test void ConservativeFenceMustBeScopedAndCoordinatesNeverWrap() {
        ObjectNode narrow = context(); ((ObjectNode) narrow.path("scope").path("regions").get(0)).putArray("min").add(0).add(64).add(0);
        AtomicInteger reads = new AtomicInteger();
        ContractException scope = assertThrows(ContractException.class, () -> observe(narrow, input(), position -> { reads.incrementAndGet(); return air(); }, () -> { }));
        assertEquals("SCOPE_DENIED", scope.code()); assertEquals(0, reads.get());
        ObjectNode edge = input(); edge.putArray("position").add(Integer.MAX_VALUE).add(64).add(0);
        ContractException overflow = assertThrows(ContractException.class, () -> observe(context(), edge, position -> air(), () -> { }));
        assertEquals("POSITION_INVALID", overflow.code());
    }

    @Test void GetterFailureAndCurrentnessFailureRetainBothTypedCauses() {
        ContractException primary = new ContractException("CELL_READ_FAILED", "Fixture getter failed");
        ContractException revoked = new ContractException("CANCELLATION_REQUESTED", "Fixture request ended");
        AtomicInteger phase = new AtomicInteger();
        ContractException actual = assertThrows(ContractException.class, () -> observe(context(), input(), position -> { phase.set(1); throw primary; },
                () -> { if (phase.get() == 1) throw revoked; }));
        assertSame(primary, actual); assertEquals(1, actual.getSuppressed().length); assertSame(revoked, actual.getSuppressed()[0]);
        AtomicInteger reads = new AtomicInteger();
        ContractException stopped = assertThrows(ContractException.class, () -> observe(context(), input(), position -> { reads.incrementAndGet(); return air(); },
                () -> { if (reads.get() == 1) throw revoked; }));
        assertSame(revoked, stopped); assertEquals(1, reads.get());
    }

    private static ObjectNode observe(ObjectNode context, ObjectNode input, OwnedBlockPatchPreflight.Cells cells, Runnable checkpoint) {
        ObjectNode facts = ContractJson.newObject().put("registryGeneration", GENERATION); facts.set("environment", context.path("environment").deepCopy());
        return OwnedBlockPatchPreflight.observe(context, input, facts, HOST, IMPL, GENERATION, cells, () -> 17, checkpoint);
    }
    private static OwnedBlockPatchPreflight.Cell air() { return new OwnedBlockPatchPreflight.Cell(state("minecraft:air"), "vanilla_air", true, true); }
    private static ObjectNode state(String id) { ObjectNode value = ContractJson.newObject().put("blockId", id); value.putObject("properties"); return value; }
    private static ObjectNode input() {
        ObjectNode value = ContractJson.newObject().put("dimension", "minecraft:overworld").put("expectedRegistryGeneration", GENERATION);
        value.putArray("position").add(0).add(64).add(0); value.set("expectedState", state("minecraft:air")); value.set("desiredState", state("minecraft:stone")); return value;
    }
    private static ObjectNode context() {
        ObjectNode value = ContractJson.newObject().put("contextId", "context-direct-fixture").put("contextDigest", "c".repeat(64)).put("dimension", "minecraft:overworld");
        value.putObject("environment").put("worldId", "world-direct-fixture");
        ObjectNode region = value.putObject("scope").putArray("regions").addObject().put("dimension", "minecraft:overworld")
                .put("contextId", "context-direct-fixture").put("worldId", "world-direct-fixture");
        region.putArray("min").add(Integer.MIN_VALUE).add(Integer.MIN_VALUE).add(Integer.MIN_VALUE);
        region.putArray("maxExclusive").add((long) Integer.MAX_VALUE + 1).add((long) Integer.MAX_VALUE + 1).add((long) Integer.MAX_VALUE + 1);
        return value;
    }
}
