package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

/** A host capability. Live target access is only valid inside onGameThread's guarded callback. */
public interface LocalContext {
    String principalRef();
    String sessionEpoch();
    /** A copy of the installed authority-owned wire context, never a caller-supplied platform receiver. */
    ObjectNode executionContext();
    boolean cancellationRequested();
    void requirePermission(String permission);
    void requireGameThread();
    void checkActive();
    <T> CompletionStage<T> onGameThread(Supplier<T> action);
    <T> String createHandle(String type, T platformObject, Class<T> expectedClass);
    <T> T resolveHandle(String token, String type, Class<T> expectedClass);
    /** Known mutation evidence is append-only and separate from provider output. */
    void recordEffect(ObjectNode observation);
    /** Must be called immediately before the first actual mutation. */
    void beginMutation();
    /** Captures an opaque provider token in native history; only the public immutable receipt is returned. */
    default ObjectNode captureUndoToken(ObjectNode privateProviderToken) {
        throw new ContractException("RECOVERY_UNSUPPORTED", "This local context does not support provider undo tokens");
    }
}
