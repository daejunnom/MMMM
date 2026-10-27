package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 실제 session close의 private owner cleanup 수명만 검사한다. 게임 권한을 만들지 않는다. */
final class HostSessionCloseTest {
    private static HostSession owner() {
        return new HostSession("fixture", "fixture", "fixture", "server", UUID.randomUUID(), Set.of(), false);
    }
    private static ObjectNode context() throws IOException {
        Path source = Path.of(System.getProperty("mmmm.checkout"), "examples", "invocation.json");
        try (var input = Files.newInputStream(source)) {
            return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1)).path("context"));
        }
    }
    private static HostSession installedOwner(ContractJson contracts, ObjectNode context) {
        var environment = context.path("environment");
        HostSession owner = new HostSession(context.path("principalRef").asText(), environment.path("sessionEpoch").asText(),
                environment.path("gameInstanceId").asText(), environment.path("side").asText(), UUID.randomUUID(), Set.of(), false);
        owner.installContext(contracts, context); return owner;
    }
    // 닫힌 public accessor는 context 정리 전후를 구분하지 못하므로 이 두 실제 보관 필드만 검사한다.
    private static void contextStorage(HostSession owner, boolean cleared) {
        try {
            var contexts = HostSession.class.getDeclaredField("contexts"); contexts.setAccessible(true);
            var contextBytes = HostSession.class.getDeclaredField("contextBytes"); contextBytes.setAccessible(true);
            Map<?, ?> stored = (Map<?, ?>) contexts.get(owner);
            assertEquals(cleared ? 0 : 1, stored.size());
            if (cleared) assertEquals(0, contextBytes.getInt(owner)); else assertTrue(contextBytes.getInt(owner) > 0);
        } catch (ReflectiveOperationException failure) { throw new AssertionError(failure); }
    }
    @Test void alreadyClosedOwnerRunsItsLateCleanupOnceOutsideTheSessionMonitor() {
        HostSession owner = owner(); AtomicInteger calls = new AtomicInteger(); owner.close();
        owner.whenClosed(() -> {
            assertTrue(owner.closed()); assertFalse(Thread.holdsLock(owner)); calls.incrementAndGet(); owner.close();
        });
        owner.close(); assertEquals(1, calls.get());
        assertThrows(IllegalStateException.class, () -> owner.whenClosed(() -> fail("Another owner cannot replace cleanup")));
    }
    @Test void registeredCleanupCanReenterCloseWithoutHoldingTheSessionMonitor() {
        HostSession owner = owner(); AtomicInteger calls = new AtomicInteger();
        owner.whenClosed(() -> {
            assertTrue(owner.closed()); assertFalse(Thread.holdsLock(owner)); calls.incrementAndGet(); owner.close();
        });
        owner.close(); owner.close(); assertEquals(1, calls.get());
    }
    @Test void lateCleanupObservesInstalledContextStorageAlreadyCleared() throws IOException {
        HostSession owner = installedOwner(new ContractJson(), context()); AtomicInteger calls = new AtomicInteger();
        contextStorage(owner, false); owner.close();
        owner.whenClosed(() -> {
            assertTrue(owner.closed()); assertFalse(Thread.holdsLock(owner)); contextStorage(owner, true); calls.incrementAndGet();
        });
        assertEquals(1, calls.get());
    }
    @Test void concurrentCloseAndRegistrationCannotLoseOrDuplicateOwnerCleanup() throws Exception {
        ContractJson contracts = new ContractJson(); ObjectNode context = context();
        for (int attempt = 0; attempt < 16; attempt++) {
            HostSession owner = installedOwner(contracts, context); AtomicInteger calls = new AtomicInteger();
            contextStorage(owner, false);
            CompletableFuture<Void> start = new CompletableFuture<>();
            var register = start.thenRunAsync(() -> owner.whenClosed(() -> {
                assertTrue(owner.closed()); assertFalse(Thread.holdsLock(owner)); contextStorage(owner, true); calls.incrementAndGet(); owner.close();
            }));
            var close = start.thenRunAsync(owner::close);
            start.complete(null); CompletableFuture.allOf(register, close).get(5, TimeUnit.SECONDS);
            owner.close(); assertTrue(owner.closed()); assertEquals(1, calls.get());
        }
    }
}
