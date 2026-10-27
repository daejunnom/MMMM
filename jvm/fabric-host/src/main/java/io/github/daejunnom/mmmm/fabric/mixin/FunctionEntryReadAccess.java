package io.github.daejunnom.mmmm.fabric.mixin;

import com.mojang.brigadier.context.ContextChain;

/** The original arguments of the actual native Unbound constructor, not a parser or grant. */
public interface FunctionEntryReadAccess {
    String mmmm$originalCommandInput();
    ContextChain<?> mmmm$compiledContextChain();
}
