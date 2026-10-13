package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;

/** The host validates source provenance and schemas before issuing a binding. */
@FunctionalInterface
public interface Registrar {
    void action(JsonNode descriptor, ActionHandler handler, OptionalCallbacks callbacks);
    /** Explicit source-to-undo relationship in the same trusted provider binding. */
    default void undoAction(String sourceActionId, String undoActionId) {
        throw new ContractException("RECOVERY_UNSUPPORTED", "This registrar has no provider undo registration");
    }
}
