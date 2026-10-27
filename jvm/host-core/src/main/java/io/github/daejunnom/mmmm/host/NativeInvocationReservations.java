package io.github.daejunnom.mmmm.host;

import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Authority-neutral sticky ownership for one frozen approval. This object has
 * no context, resource, external-target or permission grant. Its private owner
 * must validate those typed bindings before admit; constructing this object or
 * inspecting a candidate never authorizes an Invocation or records a claim.
 */
public final class NativeInvocationReservations {
    private record Reservation(String invocationId, String wireDigest) { }
    private final Instant expiresAt;
    private final Clock clock;
    private final Map<String, Reservation> reservations = new HashMap<>();
    private final Map<String, String> invocationSteps = new HashMap<>();
    private String operationId;
    private long generation;

    /** An exact local inspection, not an authority proof or an admitted Invocation. */
    public static final class Candidate {
        private final NativeInvocationReservations owner;
        private final long generation;
        private final String step, invocation, operation, digest;
        private Candidate(NativeInvocationReservations owner, long generation, Invocation invocation, String digest) {
            this.owner = owner; this.generation = generation; this.step = invocation.stepId();
            this.invocation = invocation.invocationId(); this.operation = invocation.operationId(); this.digest = digest;
        }
    }

    public NativeInvocationReservations(Instant expiresAt, Clock clock) {
        this.expiresAt = Objects.requireNonNull(expiresAt); this.clock = Objects.requireNonNull(clock);
    }

    /** Pure check; retains the original rebound/expiry ordering without admission. */
    public synchronized Candidate inspect(Invocation invocation, boolean write) {
        String digest = ContractJson.digest(invocation.wire());
        Reservation previous = reservations.get(invocation.stepId());
        if (previous != null && (!previous.invocationId().equals(invocation.invocationId())
                || !previous.wireDigest().equals(digest))) throw rebound();
        if (operationId != null && !operationId.equals(invocation.operationId())) throw rebound();
        String previousStep = invocationSteps.get(invocation.invocationId());
        if (previousStep != null && !previousStep.equals(invocation.stepId())) throw rebound();
        if (!clock.instant().isBefore(expiresAt) && (write || previous == null)) throw expired();
        return new Candidate(this, generation, invocation, digest);
    }

    /** Called under the owning approval's admission lock after its exact scope checks. */
    public synchronized boolean admit(Candidate candidate) {
        if (candidate == null || candidate.owner != this || candidate.generation != generation) throw rebound();
        if (reservations.containsKey(candidate.step)) return false;
        // An owner lock preserves reservation order, but cannot stop wall time.
        // A first claim must still be live at the actual mutation boundary.
        if (!clock.instant().isBefore(expiresAt)) throw expired();
        operationId = candidate.operation;
        reservations.put(candidate.step, new Reservation(candidate.invocation, candidate.digest));
        invocationSteps.put(candidate.invocation, candidate.step);
        generation++;
        return true;
    }

    /** Historical exact identity only; this never creates a reservation or refreshes expiry. */
    public synchronized boolean containsExact(Invocation invocation) {
        Reservation previous = reservations.get(invocation.stepId());
        return previous != null && previous.invocationId().equals(invocation.invocationId())
                && previous.wireDigest().equals(ContractJson.digest(invocation.wire()))
                && invocation.operationId().equals(operationId);
    }

    private static ContractException rebound() { return new ContractException("NATIVE_APPROVAL_REBOUND", "A frozen approval cannot be rebound to another operation or invocation"); }
    private static ContractException expired() { return new ContractException("NATIVE_APPROVAL_EXPIRED", "The frozen plan approval has expired"); }
}
