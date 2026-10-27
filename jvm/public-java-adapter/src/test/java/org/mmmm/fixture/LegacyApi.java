package org.mmmm.fixture;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/** Own no-SDK fixture: real static initialization, invocation and independently controlled async completion. */
public final class LegacyApi {
    private static int calls;
    private static final CompletableFuture<Map<String, Object>> FUTURE = new CompletableFuture<>();
    static { System.setProperty("mmmm.javaadapter.fixture.initialized", "yes"); }
    private LegacyApi() { }
    public static Map<String, Object> echo(String text) { calls++; return Map.of("text", text); }
    public static int add(int left, int right) { calls++; return Math.addExact(left, right); }
    public static CompletionStage<Map<String, Object>> later(String text) { calls++; return FUTURE; }
    public static void finishLater(String text) { FUTURE.complete(Map.of("text", text)); }
    public static int calls() { return calls; }
    public static Map<String, Object> rejectsThread(Thread value) { throw new AssertionError("Unsupported signature must never execute"); }
    public static Map<String, Object> throwsAfterDispatch(String text) { calls++; throw new IllegalStateException("fixture failure"); }
}
