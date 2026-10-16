package io.github.daejunnom.mmmm.javaadapter;

/** Fixed MVP bounds; these do not sandbox arbitrary code already running in the JVM. */
public final class AdapterLimits {
    public static final int JAR_BYTES = 32 * 1024 * 1024;
    public static final int EXPANDED_BYTES = 64 * 1024 * 1024;
    public static final int JAR_ENTRIES = 512;
    public static final int CLASSES = 256;
    public static final int CLASS_BYTES = 2 * 1024 * 1024;
    public static final int ARGUMENTS = 32;
    public static final int JSON_BYTES = 256 * 1024;
    public static final int JSON_NODES = 4096;
    public static final int JSON_DEPTH = 16;
    public static final int JOBS = 64;
    private AdapterLimits() { }
}
