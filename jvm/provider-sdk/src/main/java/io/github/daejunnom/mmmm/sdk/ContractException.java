package io.github.daejunnom.mmmm.sdk;

/** A deterministic boundary failure. The message must not contain credentials or local paths. */
public final class ContractException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public ContractException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() { return code; }
}
