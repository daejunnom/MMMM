// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

/** Owned startup fixture: no initializer, state, native methods or external effects. */
public final class DefinitionStartupProbe {
    private DefinitionStartupProbe() { }
    static int identity(int value) { return value; }

    /** Fixed noncapturing factory; the startup fixture never executes run(). */
    public static Runnable ownedRunnable() {
        return () -> { };
    }
}
