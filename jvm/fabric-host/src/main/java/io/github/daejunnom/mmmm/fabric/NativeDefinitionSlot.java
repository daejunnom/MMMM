package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.host.HostSession;
import java.util.Objects;

/** 원래 collection ticket만 게시할 수 있는 단일 private 원자료 소유 슬롯이다. */
final class NativeDefinitionSlot {
    static final class Ticket {
        private final HostSession owner;
        private final Object server;
        private final String contextId;
        private final String contextDigest;
        private final String epoch;
        private final long generation;
        private Ticket(HostSession owner, Object server, String contextId, String contextDigest, String epoch, long generation) {
            this.owner = owner; this.server = server; this.contextId = contextId; this.contextDigest = contextDigest;
            this.epoch = epoch; this.generation = generation;
        }
    }
    private Ticket current;
    // Ticket은 Class/raw를 소유하지 않는다. retire/교체 즉시 슬롯의 강한 참조를 해제한다.
    private NativeDefinitionCollector.Snapshot snapshot;

    synchronized Ticket begin(HostSession owner, Object server, String contextId, String contextDigest, String epoch, long generation) {
        Objects.requireNonNull(owner).checkOpen();
        Ticket ticket = new Ticket(owner, Objects.requireNonNull(server), Objects.requireNonNull(contextId),
                Objects.requireNonNull(contextDigest), Objects.requireNonNull(epoch), generation);
        current = ticket; snapshot = null; return ticket;
    }
    synchronized boolean publish(Ticket ticket, NativeDefinitionCollector.Snapshot observed) {
        Objects.requireNonNull(observed);
        if (current != ticket) return false;
        if (ticket.owner.closed()) { current = null; snapshot = null; return false; }
        snapshot = observed; return true;
    }
    synchronized void retire(Ticket ticket) {
        if (current == ticket) { current = null; snapshot = null; }
    }
    synchronized void retire(HostSession owner) {
        if (current != null && current.owner == owner) { current = null; snapshot = null; }
    }
    synchronized void retireAll() { current = null; snapshot = null; }
    synchronized boolean hasRawObservation(HostSession owner, Object server, String contextId, String contextDigest, String epoch, long generation) {
        return current != null && current.owner == owner && !owner.closed() && current.server == server
                && current.contextId.equals(contextId) && current.contextDigest.equals(contextDigest)
                && current.epoch.equals(epoch) && current.generation == generation
                && snapshot != null && snapshot.completed() && snapshot.hasRawObservation();
    }
    synchronized long retainedBytes() { return snapshot == null ? 0 : snapshot.retainedBytes(); }
}
