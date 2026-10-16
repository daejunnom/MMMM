package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Pure negative boundaries. These fixtures cannot mint an actual prepared or completed run. */
final class NativeCalibrationSourceTest {
    private final ContractJson contracts = new ContractJson();
    private final NativeCalibrationSource source = new NativeCalibrationSource(contracts);
    @Test void missingTypedIssuerPrecedesInvocationOrSourceAccess() throws IOException {
        var inputs = inputs(); AtomicInteger checks = new AtomicInteger();
        assertEquals(NativeCalibrationSource.ISSUER_UNAVAILABLE, assertThrows(ContractException.class,
                () -> source.inspect(null, null, null, null, inputs.request(), null, null, checks::incrementAndGet)).code());
        assertEquals(2, checks.get());
        AtomicInteger lookups = new AtomicInteger();
        assertEquals(NativeCalibrationSource.ISSUER_UNAVAILABLE, assertThrows(ContractException.class,
                () -> inspect(inputs, (context, id) -> { lookups.incrementAndGet(); assertEquals(inputs.original().invocationId(), id); return null; })).code());
        assertEquals(1, lookups.get());
    }
    @Test void callerCasAndProofFieldsAreRejectedBeforeLookup() throws IOException {
        for (String field : Set.of("sourceResource", "readbackSourceDigest", "programDigest", "commandsDigest", "callerVerified")) {
            var inputs = inputs(); inputs.request().put(field, "f".repeat(64)); AtomicInteger calls = new AtomicInteger();
            assertEquals("CALIBRATION_RUN_SOURCE_INVALID", assertThrows(ContractException.class,
                    () -> inspect(inputs, (context, id) -> { calls.incrementAndGet(); return null; })).code());
            assertEquals(0, calls.get());
        }
    }
    @Test void staleOriginalAndCurrentPinsCannotReachLookup() throws IOException {
        for (String field : Set.of("invocationId", "invocationDigest", "expectedRuntimeSourceFactsDigest", "expectedRegistryGeneration")) {
            var inputs = inputs(); inputs.request().put(field, field.equals("invocationId") ? "another-original" : field.equals("expectedRegistryGeneration") ? "32" : "f".repeat(64));
            AtomicInteger calls = new AtomicInteger();
            assertEquals("CALIBRATION_RUN_SOURCE_STALE", assertThrows(ContractException.class,
                    () -> inspect(inputs, (context, id) -> { calls.incrementAndGet(); return null; })).code());
            assertEquals(0, calls.get());
        }
    }
    @Test void failedLookupAndOriginalPostControlAreBothPreserved() throws IOException {
        var inputs = inputs(); AtomicInteger checks = new AtomicInteger();
        ContractException primary = new ContractException("ACTUAL_SOURCE_FAILURE", "fixture");
        ContractException post = new ContractException("CANCELLATION_REQUESTED", "fixture");
        ContractException observed = assertThrows(ContractException.class, () -> source.inspect(inputs.context(), inputs.facts(), "a".repeat(64), "31",
                inputs.request(), inputs.original(), (context, id) -> { throw primary; }, () -> { if (checks.incrementAndGet() >= 3) throw post; }));
        assertSame(primary, observed); assertArrayEquals(new Throwable[] {post}, observed.getSuppressed());
    }
    @Test void rawJsonHasNoPreparedOrRunFactsConstructionPath() {
        for (Class<?> type : new Class<?>[] { NativeCalibrationPrepared.class, NativeCalibrationRunFacts.class, NativeCalibrationRunner.CompletedRun.class })
            for (var constructor : type.getDeclaredConstructors()) assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        assertEquals("mmmm.native.calibration-run-source/3", NativeCalibrationSource.FORMAT);
        assertEquals(NativeCalibrationRunFacts.class, NativeCalibrationSource.Issuer.class.getDeclaredMethods()[0].getReturnType());
    }
    @Test void sourceCapacityIncludesTheOriginalWholeRpcNodeAndByteBounds() {
        ObjectNode capacityOnly = ContractJson.newObject(); var nodes = capacityOnly.putArray("capacityOnly");
        for (int index = 0; index < 4086; index++) nodes.add(index);
        assertDoesNotThrow(() -> NativeCalibrationRunFacts.bounded(capacityOnly));
        nodes.add(4086);
        assertEquals("CALIBRATION_RUN_SOURCE_LIMIT", assertThrows(ContractException.class,
                () -> NativeCalibrationRunFacts.bounded(capacityOnly)).code());
        assertEquals("CALIBRATION_RUN_SOURCE_LIMIT", assertThrows(ContractException.class,
                () -> NativeCalibrationRunFacts.bounded(ContractJson.newObject().put("capacityOnly", "x".repeat(1024 * 1024)))).code());
    }
    private ObjectNode inspect(Inputs inputs, NativeCalibrationSource.Issuer issuer) {
        return source.inspect(inputs.context(), inputs.facts(), "a".repeat(64), "31", inputs.request(), inputs.original(), issuer, () -> { });
    }
    private record Inputs(Invocation original, ObjectNode context, ObjectNode facts, ObjectNode request) { }
    private Inputs inputs() throws IOException {
        Path path = Path.of("examples", "invocation.json"); if (!Files.isRegularFile(path)) path = Path.of("..", "..", "examples", "invocation.json");
        Invocation original = new Invocation(contracts, ContractJson.parse(Files.readAllBytes(path))); ObjectNode context = original.context();
        ObjectNode facts = ContractJson.newObject().put("registryGeneration", "31").put("observedAt", "2026-10-14T00:00:00Z");
        facts.set("environment", context.get("environment").deepCopy());
        ObjectNode request = ContractJson.newObject().put("kind", "calibration_run_source").put("invocationId", original.invocationId())
                .put("invocationDigest", ContractJson.digest(original.wire())).put("expectedRuntimeSourceFactsDigest", NativeProfileAdmission.sourceDigest(facts))
                .put("expectedRegistryGeneration", "31");
        return new Inputs(original, context, facts, request);
    }
}
