package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.util.Set;

/** Implemented by the platform host, using the actual paired player and live target state. */
public interface HostAuthority {
    boolean ready();
    ObjectNode hello();
    void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write);
    /** Trusted plan admission hook. The original Invocation never supplies a permission grant. */
    default void checkInvocation(HostSession session, Invocation invocation, boolean write) { }
    /** A write precondition check and its apply run in one game-thread execution interval. */
    void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments);
}
