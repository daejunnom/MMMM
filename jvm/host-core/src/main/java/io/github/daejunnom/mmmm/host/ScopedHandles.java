package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** Objects stay in the host. Tokens bind the paired session, immutable context, binding and Java type. */
public final class ScopedHandles {
    private record ContextOwner(String id, String digest) { }
    private record Entry(HostSession session, String binding, ContextOwner context, String type, Class<?> javaType, Object value) { }
    private final Map<String, Entry> entries = new HashMap<>();
    public synchronized <T> String create(HostSession session, String binding, ObjectNode context, String type, T value, Class<T> javaType) {
        ContextOwner owner = contextOwner(session, context);
        if (entries.size() >= 4096) throw new ContractException("HANDLE_LIMIT", "Host handle capacity is exhausted");
        if (type.isBlank() || !javaType.isInstance(value)) throw new IllegalArgumentException("Handle type mismatch");
        String token = "handle-" + UUID.randomUUID();
        entries.put(token, new Entry(session, binding, owner, type, javaType, value));
        return token;
    }
    public synchronized <T> T resolve(HostSession session, String binding, ObjectNode context, String token, String type, Class<T> javaType) {
        ContextOwner owner = contextOwner(session, context);
        Entry entry = entries.get(token);
        if (entry == null || entry.session != session || !entry.binding.equals(binding)
                || !entry.context.equals(owner) || !entry.type.equals(type) || entry.javaType != javaType) {
            throw new ContractException("HANDLE_SCOPE_MISMATCH", "Handle is missing, expired or belongs to another scope");
        }
        return javaType.cast(entry.value);
    }
    public synchronized void removeSession(HostSession session) {
        entries.entrySet().removeIf(entry -> entry.getValue().session == session);
    }
    public synchronized void clear() { entries.clear(); }
    private static ContextOwner contextOwner(HostSession session, ObjectNode context) {
        session.checkOpen();
        if (context == null || !context.path("contextId").isTextual() || !context.path("contextDigest").isTextual()) {
            throw mismatch();
        }
        ObjectNode installed;
        try { installed = session.context(context.path("contextId").asText()); }
        catch (ContractException exception) {
            if ("CONTEXT_UNKNOWN".equals(exception.code())) throw mismatch();
            throw exception;
        }
        if (!installed.equals(context)) throw mismatch();
        return new ContextOwner(installed.path("contextId").asText(), installed.path("contextDigest").asText());
    }
    private static ContractException mismatch() {
        return new ContractException("HANDLE_SCOPE_MISMATCH", "Handle context does not match an immutable installed context");
    }
}
