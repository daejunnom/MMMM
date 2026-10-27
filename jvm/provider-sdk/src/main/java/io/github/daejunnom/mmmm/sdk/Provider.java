package io.github.daejunnom.mmmm.sdk;

/** Fabric entrypoint key: mmmm:provider. Registration declares capabilities without target access. */
@FunctionalInterface
public interface Provider {
    void register(Registrar registrar);
}
