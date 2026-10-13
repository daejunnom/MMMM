package org.mmmm.fixture;

import java.util.Map;

/** A reviewed public factory is an API action; the adapter never invokes this private constructor itself. */
public class ReceiverApi {
    private ReceiverApi() { }
    public static ReceiverApi create() { return new ReceiverApi(); }
    public static ReceiverApi child() { return new Child(); }
    public Map<String, Object> echo(String text) { return Map.of("text", "receiver:" + text); }
    public static final class Child extends ReceiverApi {
        private Child() { }
        @Override public Map<String, Object> echo(String text) { throw new AssertionError("Unapproved override must never execute"); }
    }
}
