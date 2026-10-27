package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.JsonNode;

/** The host validates source provenance and schemas before issuing a binding. */
@FunctionalInterface
public interface Registrar {
    void action(JsonNode descriptor, ActionHandler handler, OptionalCallbacks callbacks);

    /** Registers an immutable typed descriptor through the host's existing registration boundary. */
    default void registerAction(ActionDescriptor descriptor, ActionHandler handler, OptionalCallbacks callbacks) {
        if (descriptor == null) throw new ContractException("CONTRACT_INVALID", "Action descriptor is required");
        action(descriptor.wire(), handler, callbacks);
    }

    /**
     * Explicit source-to-undo relationship in the same trusted provider binding. Finish all
     * registrations before trusted role inspection seals the host Registrar generation. An
     * unlinked provider_undo declaration or Recover callback has no positive ordinary role.
     */
    default void undoAction(String sourceActionId, String undoActionId) {
        throw new ContractException("RECOVERY_UNSUPPORTED", "This registrar has no provider undo registration");
    }
}
