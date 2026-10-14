package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Created only by trusted, out-of-band pairing. No RPC method can create a session or context. */
public final class HostSession {
    private final String principalRef;
    private final String epoch;
    private final String gameInstanceId;
    private final String side;
    private final UUID playerId;
    private final Set<String> permissions;
    private final boolean verifiedWriteProfile;
    private final Map<String, ObjectNode> contexts = new java.util.HashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean closeHookRegistered = new AtomicBoolean();
    private final AtomicReference<Runnable> closeHook = new AtomicReference<>();
    private int contextBytes;

    public HostSession(String principalRef, String epoch, String gameInstanceId, String side,
                       UUID playerId, Set<String> permissions, boolean verifiedWriteProfile) {
        if (!Set.of("server", "client").contains(side)) throw new IllegalArgumentException("Unsupported host side");
        this.principalRef = principalRef;
        this.epoch = epoch;
        this.gameInstanceId = gameInstanceId;
        this.side = side;
        this.playerId = playerId;
        this.permissions = Set.copyOf(permissions);
        this.verifiedWriteProfile = verifiedWriteProfile;
    }

    public String principalRef() { return principalRef; }
    public String epoch() { return epoch; }
    public String gameInstanceId() { return gameInstanceId; }
    public String side() { return side; }
    public UUID playerId() { return playerId; }
    public boolean closed() { return closed.get(); }
    public boolean verifiedWriteProfile() { return verifiedWriteProfile; }
    public boolean permits(String permission) { return permissions.contains(permission); }

    /** The trusted pairing installer receives this context from the Coordinator's authority. */
    public synchronized void installContext(ContractJson contracts, JsonNode value) {
        checkOpen();
        contracts.validate("ExecutionContext", value);
        ObjectNode context = ContractJson.object(value).deepCopy();
        int size = ContractJson.bytes(context).length;
        if (size > HostRuntime.MAX_RESULT_BYTES) throw new ContractException("CONTEXT_LIMIT", "Installed context exceeds the host byte limit");
        JsonNode environment = context.path("environment");
        if (!principalRef.equals(context.path("principalRef").asText())
                || !"game".equals(environment.path("kind").asText())
                || !epoch.equals(environment.path("sessionEpoch").asText())
                || !gameInstanceId.equals(environment.path("gameInstanceId").asText())
                || !side.equals(environment.path("side").asText())
                || !ContractJson.contextDigest(context).equals(context.path("contextDigest").asText())) {
            throw new ContractException("CONTEXT_SCOPE_MISMATCH", "The installed context does not belong to this session");
        }
        String id = context.path("contextId").asText();
        if (contexts.size() >= 256 && !contexts.containsKey(id)) {
            throw new ContractException("CONTEXT_LIMIT", "Session context capacity is exhausted");
        }
        ObjectNode previous = contexts.get(id);
        if (previous != null && !previous.equals(context)) {
            throw new ContractException("CONTEXT_CHANGED", "An immutable context ID cannot be reused for different values");
        }
        if (previous == null) {
            if (contextBytes > 8 * 1024 * 1024 - size) throw new ContractException("CONTEXT_LIMIT", "Session contexts exceed the aggregate byte limit");
            contexts.put(id, context); contextBytes += size;
        }
    }

    public synchronized ObjectNode context(String id) {
        checkOpen();
        ObjectNode context = contexts.get(id);
        if (context == null) throw new ContractException("CONTEXT_UNKNOWN", "Context is not installed for this session");
        return context.deepCopy();
    }
    /** Trusted composition installs one resource-owner cleanup; no request receives this hook. */
    public void whenClosed(Runnable ownerClose) {
        Objects.requireNonNull(ownerClose);
        if (!closeHookRegistered.compareAndSet(false, true)) throw new IllegalStateException("Session owner close hook already registered");
        closeHook.set(ownerClose);
        if (closed.get()) runCloseHook();
    }
    public void close() {
        synchronized (this) { contexts.clear(); contextBytes = 0; closed.set(true); }
        // Callback may retire a host-owned slot or reenter close. Never hold the session monitor here.
        runCloseHook();
    }
    private void runCloseHook() {
        Runnable ownerClose = closeHook.getAndSet(null);
        if (ownerClose != null) ownerClose.run();
    }
    public void checkOpen() {
        if (closed()) throw new ContractException("SESSION_EXPIRED", "The paired host session has ended");
    }
}
