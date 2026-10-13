package io.github.daejunnom.mmmm.sdk;

import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface ActionHandler {
    CompletionStage<ProviderResult> execute(Invocation invocation, LocalContext context);
}
