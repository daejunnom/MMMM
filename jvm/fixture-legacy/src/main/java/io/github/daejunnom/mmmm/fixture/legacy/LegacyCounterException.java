package io.github.daejunnom.mmmm.fixture.legacy;

import java.io.Serial;

/** A fixture failure code; neither the code nor a public result grants host authority. */
public final class LegacyCounterException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;
    private final String code;

    LegacyCounterException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() { return code; }
}
