package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import net.minecraft.nbt.CompoundTag;
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
        var cachePrimary = new ContractException("CACHE_READ_FAILED", "original native map failed");
        var cacheRead = new AtomicBoolean();
        var cache = new Cache() {
            @Override public Map<String, CompoundTag> contents(Object container) { cacheRead.set(true); throw cachePrimary; }
        };
        cache.add("mmmm");
        assertSame(cachePrimary, assertThrows(ContractException.class, () -> NativeCommandStorageCache.inspect(cache, "mmmm:calibration/int_add",
                () -> { if (cacheRead.get()) throw revoked; })));
        assertArrayEquals(new Throwable[]{revoked}, cachePrimary.getSuppressed());
    }

    @Test void completeCachedMembershipHonorsTheCapAfterAnEarlyMatchAndOriginalCheckpoint() {
        String target = "mmmm:calibration/int_add", path = "calibration/int_add"; var cache = new Cache();
        var unknown = NativeCommandStorageCache.inspect(cache, target, () -> { });
        assertEquals(NativeCommandStorageCache.State.NAMESPACE_UNKNOWN, unknown.facts().state()); assertNull(unknown.facts().cachedRoot());
        Object container = cache.add("mmmm"); Map<String, CompoundTag> contents = cache.contents(container);
        var absent = NativeCommandStorageCache.inspect(cache, target, () -> { });
        assertEquals(NativeCommandStorageCache.State.KEY_ABSENT, absent.facts().state()); assertNull(absent.facts().cachedRoot());
        assertTrue(contents.isEmpty()); // No native get or fabricated empty root is needed to establish this absence.
        assertThrows(ContractException.class, () -> unknown.checkCurrent(cache));
        contents.put(path, null);
        assertThrows(ContractException.class, () -> NativeCommandStorageCache.inspect(cache, target, () -> { })); contents.remove(path);
        var unavailable = new Cache(); unavailable.namespaces = null;
        assertEquals(NativeCommandStorageCache.State.NOT_ADMITTED, NativeCommandStorageCache.inspect(unavailable, target, () -> { }).facts().state());
        CompoundTag root = new CompoundTag(); contents.put(path, root);
        assertThrows(ContractException.class, () -> absent.checkCurrent(cache));
        var present = NativeCommandStorageCache.inspect(cache, target, () -> { });
        assertEquals(NativeCommandStorageCache.State.PRESENT, present.facts().state()); assertSame(root, present.facts().cachedRoot());
        present.checkComplete(cache, () -> { }); assertEquals(1, contents.size()); assertSame(root, contents.get(path));
        Map<String, Object> namespaces = cache.namespaces;
        cache.namespaces = new LinkedHashMap<>(namespaces);
        assertThrows(ContractException.class, () -> present.checkCurrent(cache)); cache.namespaces = namespaces;
        Object replacement = new Object(); cache.namespaces.put("mmmm", replacement); cache.containers.put(replacement, contents);
        assertThrows(ContractException.class, () -> present.checkCurrent(cache)); cache.namespaces.put("mmmm", container);
        cache.containers.put(container, new LinkedHashMap<>(contents));
        assertThrows(ContractException.class, () -> present.checkCurrent(cache)); cache.containers.put(container, contents);
        contents.put(path, new CompoundTag());
        assertThrows(ContractException.class, () -> present.checkCurrent(cache)); contents.put(path, root);
        Object unrelated = cache.add("fixture"); Map<String, CompoundTag> other = cache.contents(unrelated);
        for (int index = 0; index < 4095; index++) other.put("other/" + index, root);
        present.checkComplete(cache, () -> { }); // The early target match cannot omit another namespace's keys.
        other.put("past-the-cap", root);
        assertEquals("CALIBRATION_STATE_LIMIT", assertThrows(ContractException.class, () -> present.checkComplete(cache, () -> { })).code());
        other.remove("past-the-cap");
        var emptyNamespaces = new Cache(); emptyNamespaces.add("mmmm");
        for (int index = 1; index < 4096; index++) emptyNamespaces.add("empty" + index);
        assertEquals(NativeCommandStorageCache.State.KEY_ABSENT, NativeCommandStorageCache.inspect(emptyNamespaces, target, () -> { }).facts().state());
        emptyNamespaces.add("past-the-cap");
        assertEquals("CALIBRATION_STATE_LIMIT", assertThrows(ContractException.class, () -> NativeCommandStorageCache.inspect(emptyNamespaces, target, () -> { })).code());
        var checks = new AtomicInteger(); var stopped = new ContractException("ORIGINAL_CANCELLED", "original cancelled");
        assertSame(stopped, assertThrows(ContractException.class, () -> NativeCommandStorageCache.inspect(cache, target,
                () -> { if (checks.incrementAndGet() >= 4) throw stopped; })));
        assertEquals(5, checks.get()); // The original cancellation is checked once more after the failed read.
    }

    /** Synthetic cached maps exercise the comparison port only, never an actual Read or game ImagePair. */
    private static class Cache implements NativeCommandStorageCache.View {
        Map<String, Object> namespaces = new LinkedHashMap<>();
        final Map<Object, Map<String, CompoundTag>> containers = new IdentityHashMap<>();
        Object add(String namespace) { Object container = new Object(); namespaces.put(namespace, container); containers.put(container, new LinkedHashMap<>()); return container; }
        @Override public Map<String, ?> namespaces() { return namespaces; }
        @Override public Map<String, CompoundTag> contents(Object container) { return containers.get(container); }
        @Override public void checkCurrent() { }
    }
}
