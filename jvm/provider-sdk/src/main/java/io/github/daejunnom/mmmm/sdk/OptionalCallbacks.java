package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.concurrent.CompletionStage;

/** Missing callbacks mean unsupported. prepare is observational and must not write then undo. */
public record OptionalCallbacks(Prepare prepare, Poll poll, Cancel cancel, Read read, Recover recover) {
    public OptionalCallbacks(Prepare prepare, Poll poll, Cancel cancel) { this(prepare, poll, cancel, null, null); }
    public OptionalCallbacks(Prepare prepare, Poll poll, Cancel cancel, Read read) { this(prepare, poll, cancel, read, null); }
    public static OptionalCallbacks none() { return new OptionalCallbacks(null, null, null); }
    @FunctionalInterface public interface Read {
        CompletionStage<ProviderResult> read(RegisteredActionRead request, LocalContext readOnlyContext);
    }
    @FunctionalInterface public interface Recover {
        CompletionStage<ProviderResult> recover(Invocation newInvocation, ObjectNode privateProviderToken, LocalContext context);
    }
    @FunctionalInterface public interface Prepare {
        CompletionStage<ObjectNode> prepare(Invocation invocation, LocalContext readOnlyContext);
    }
    @FunctionalInterface public interface Poll {
        CompletionStage<ProviderResult> poll(String hostScopedHandle, LocalContext context);
    }
    @FunctionalInterface public interface Cancel {
        CompletionStage<ObjectNode> cancel(String hostScopedHandle, LocalContext context);
    }
}
