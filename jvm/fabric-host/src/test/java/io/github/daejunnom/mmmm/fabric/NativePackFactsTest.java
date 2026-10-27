package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.fabric.mixin.FixedPathPackReadAccess;
import io.github.daejunnom.mmmm.fabric.mixin.OverlayedPackReadAccess;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import net.minecraft.server.packs.OverlayedPackResources;
import net.minecraft.server.packs.PackMetadataResources;
import net.minecraft.server.packs.PackResources;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 기존 정의 수집 port는 실제 pack type/accessor 경계를 거치지 않는다.
 * 이 fixture는 resource I/O나 실제 게임의 known pack 권한을 만들지 않고 거절·원 제어만 검사한다. */
final class NativePackFactsTest {
    private static PackResources opaque(AtomicInteger calls, Class<?>... additional) {
        Class<?>[] interfaces = new Class<?>[additional.length + 1];
        interfaces[0] = PackResources.class;
        System.arraycopy(additional, 0, interfaces, 1, additional.length);
        return (PackResources) Proxy.newProxyInstance(PackResources.class.getClassLoader(), interfaces,
                (proxy, method, arguments) -> { calls.incrementAndGet(); throw new AssertionError("허가하지 않은 pack port 호출"); });
    }

    private static NativePackFacts.Observation observe(PackResources pack, NativeSourceFacts.Checkpoint checkpoint,
                                                      AtomicInteger roots, int allowance) {
        return NativePackFacts.observe(pack, checkpoint, root -> {
            roots.incrementAndGet(); throw new AssertionError("거절한 type은 root에 접근할 수 없습니다");
        }, allowance, 256 * 1024);
    }

    @Test void customImplementationCannotImpersonateAnExactTypeByExposingItsAccessor() {
        AtomicInteger calls = new AtomicInteger(); AtomicInteger roots = new AtomicInteger();
        var observed = observe(opaque(calls, FixedPathPackReadAccess.class), () -> { }, roots, 256);
        assertEquals("unknown", observed.facts().path("status").asText());
        assertEquals("PACK_IMPLEMENTATION_UNSUPPORTED", observed.facts().path("reason").asText());
        assertTrue(observed.facts().path("nodes").isEmpty()); assertTrue(observed.facts().path("rootNode").isNull());
        assertEquals(0, calls.get()); assertEquals(0, roots.get());
    }

    @Test void exactOverlayWithoutInstalledReadAccessorRemainsUnknownWithoutExecutingItsResources() {
        AtomicInteger calls = new AtomicInteger(); AtomicInteger roots = new AtomicInteger();
        PackResources base = opaque(calls);
        var observed = observe(new OverlayedPackResources(base, List.of(base)), () -> { }, roots, 256);
        assertEquals("NATIVE_PACK_ACCESS_UNAVAILABLE", observed.facts().path("reason").asText());
        assertEquals("unknown", observed.facts().path("filter").path("status").asText());
        assertEquals("NATIVE_FILTER_MAPPING_UNOBSERVED", observed.facts().path("filter").path("reason").asText());
        observed.revalidate().run();
        assertEquals(0, calls.get()); assertEquals(0, roots.get());
    }

    @Test void subclassCannotSupplyAnApprovedGraphEvenWhenItsAccessorLooksAvailable() {
        AtomicInteger calls = new AtomicInteger(); AtomicInteger roots = new AtomicInteger();
        PackResources base = opaque(calls);
        class CustomOverlay extends OverlayedPackResources implements OverlayedPackReadAccess {
            CustomOverlay() { super(base, List.of()); }
            @Override public PackMetadataResources mmmm$primaryPackMetadataResources() { calls.incrementAndGet(); return base; }
            @Override public List<PackResources> mmmm$packResourcesStack() { calls.incrementAndGet(); return List.of(base); }
        }
        var observed = observe(new CustomOverlay(), () -> { }, roots, 256);
        assertEquals("PACK_IMPLEMENTATION_UNSUPPORTED", observed.facts().path("reason").asText());
        assertEquals(0, calls.get()); assertEquals(0, roots.get());
    }

    @Test void originalControlStopsBeforeAccessAndAfterAnUnknownObservationWithoutChangingItsThrowable() {
        AtomicInteger calls = new AtomicInteger(); AtomicInteger roots = new AtomicInteger();
        ContractException original = new ContractException("CANCELLATION_REQUESTED", "원 pack 관측이 끝났습니다");
        assertSame(original, assertThrows(ContractException.class,
                () -> observe(opaque(calls), () -> { throw original; }, roots, 256)));
        AtomicBoolean stopped = new AtomicBoolean();
        var observed = observe(opaque(calls), () -> { if (stopped.get()) throw original; }, roots, 256);
        stopped.set(true);
        assertSame(original, assertThrows(ContractException.class, observed.revalidate()::run));
        assertEquals(0, calls.get()); assertEquals(0, roots.get());
    }

    @Test void exhaustedSharedEntryAllowanceReturnsOnlyAClosedUnknownGraph() {
        AtomicInteger calls = new AtomicInteger(); AtomicInteger roots = new AtomicInteger();
        var observed = observe(opaque(calls), () -> { }, roots, 0);
        assertEquals("PACK_FACTS_LIMIT", observed.facts().path("reason").asText());
        assertEquals(0, observed.entries()); assertTrue(observed.facts().path("nodes").isEmpty());
        assertTrue(observed.facts().path("rootNode").isNull());
        assertTrue(ContractJson.bytes(observed.facts()).length < 256 * 1024);
        assertEquals(0, calls.get()); assertEquals(0, roots.get());
    }

    @Test void unsafeRootPrefixesAreRejectedLiterallyInsteadOfNormalizedIntoPublicFacts() throws Exception {
        var method = NativeSourceFacts.class.getDeclaredMethod("safePackPrefix", String.class);
        method.setAccessible(true);
        for (String prefix : List.of("", "data", "builtin/overlay_v1", "assets/café")) {
            assertEquals(true, method.invoke(null, prefix));
        }
        for (String prefix : List.of("/data", "data/", "data//nested", "data/../nested", "data\\nested", "data:stream",
                "data/name.", "data/name ", "data/NUL.json", "data/CON", "data/a?b", "data/.env", "data/.ssh",
                "data/credentials", "data/cafe\u0301", "a".repeat(1025))) {
            assertEquals(false, method.invoke(null, prefix));
        }
        // default filesystem 경로를 receipt 연결로 바꾸지 않는 실제 private installation 경계다.
        var constructor = NativeSourceFacts.class.getDeclaredConstructor(NativeSourceFacts.Checkpoint.class);
        constructor.setAccessible(true);
        var facts = constructor.newInstance((NativeSourceFacts.Checkpoint) () -> { });
        var root = NativeSourceFacts.class.getDeclaredMethod("packRoot", Path.class);
        root.setAccessible(true);
        var link = (NativePackFacts.RootLink) root.invoke(facts, Path.of("."));
        assertEquals("PACK_ROOT_NOT_ZIPFS", link.reason()); assertNull(link.sourceId()); assertNull(link.memberPrefix());
    }
}
