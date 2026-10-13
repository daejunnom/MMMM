package io.github.daejunnom.mmmm.host;

/** Platform queue only; this does not own a scheduler or operation journal. */
public interface GameThread {
    boolean isSameThread();
    void execute(Runnable action);
}
