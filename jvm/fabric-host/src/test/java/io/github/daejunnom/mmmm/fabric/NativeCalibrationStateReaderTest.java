package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Pure current-context/cache helpers used by full images, never actual owner or game evidence. */
final class NativeCalibrationStateReaderTest {
    @Test void firstOwnerLookupAndMismatchKeepTheOriginalAndSubsequentControlFailure() {
        var primary = new ContractException("CONTEXT_READ_FAILED", "original lookup failed");
        var revoked = new ContractException("SOURCE_REVOKED", "original source revoked");
        var lookedUp = new AtomicBoolean(); var reads = new AtomicInteger(); ObjectNode supplied = ContractJson.newObject().put("contextId", "fixture");
        assertSame(primary, assertThrows(ContractException.class, () -> NativeCalibrationStateReader.withContext(
                () -> { lookedUp.set(true); throw primary; }, supplied,
                () -> { if (lookedUp.get()) throw revoked; }, context -> reads.incrementAndGet())));
        assertArrayEquals(new Throwable[]{revoked}, primary.getSuppressed()); assertEquals(0, reads.get());
        lookedUp.set(false);
        ContractException mismatch = assertThrows(ContractException.class, () -> NativeCalibrationStateReader.withContext(
                () -> { lookedUp.set(true); return supplied.deepCopy().put("contextId", "replacement"); }, supplied,
                () -> { if (lookedUp.getAndSet(false)) throw revoked; }, context -> reads.incrementAndGet()));
        assertEquals("CALIBRATION_STATE_CONTEXT_CHANGED", mismatch.code()); assertArrayEquals(new Throwable[]{revoked}, mismatch.getSuppressed());
        assertEquals(0, reads.get());
        assertSame(revoked, assertThrows(ContractException.class, () -> NativeCalibrationStateReader.withContext(
                () -> { throw new AssertionError("A stopped request must not read owner context"); }, supplied,
                () -> { throw revoked; }, context -> reads.incrementAndGet())));
    }

    @Test void completeCachedMembershipHonorsTheCapAfterAnEarlyMatchAndOriginalCheckpoint() {
        String target = "mmmm:calibration/int_add"; var exact = new ArrayList<String>(); exact.add(target);
        for (int index = 1; index < 4096; index++) exact.add("fixture:other/" + index);
        assertEquals(target, NativeCalibrationStateReader.cachedKey(exact.iterator(), target, () -> { }));
        assertNull(NativeCalibrationStateReader.cachedKey(List.of("fixture:other").iterator(), target, () -> { }));
        exact.add("fixture:past-the-cap");
        assertEquals("CALIBRATION_STATE_LIMIT", assertThrows(ContractException.class,
                () -> NativeCalibrationStateReader.cachedKey(exact.iterator(), target, () -> { })).code());
        assertThrows(ContractException.class, () -> NativeCalibrationStateReader.cachedKey(List.of(target, target).iterator(), target, () -> { }));
        var checks = new AtomicInteger(); var stopped = new ContractException("ORIGINAL_CANCELLED", "original cancelled");
        assertSame(stopped, assertThrows(ContractException.class, () -> NativeCalibrationStateReader.cachedKey(exact.iterator(), target,
                () -> { if (checks.incrementAndGet() == 4) throw stopped; })));
        assertEquals(4, checks.get());
    }
}
