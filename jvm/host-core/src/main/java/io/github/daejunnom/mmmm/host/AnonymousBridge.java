package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Only an exact approved MMMM executable is launched. Secrets cross anonymous pipes, never public JSON. */
public final class AnonymousBridge {
    public static final int MAX_FRAME = 1024 * 1024;
    /** A mode selects one fixed bridge command and authority envelope; callers cannot supply arguments. */
    public enum Mode {
        PAIRING("--stdio-bootstrap", "host_pairing_offer", "host_pairing_authority"),
        APPLY_APPROVAL("--stdio-approval", "host_apply_approval_offer", "host_apply_approval_authority");
        private final String argument;
        private final String offerKind;
        private final String authorityKind;
        Mode(String argument, String offerKind, String authorityKind) {
            this.argument = argument; this.offerKind = offerKind; this.authorityKind = authorityKind;
        }
    }
    @FunctionalInterface public interface Installer {
        CompletionStage<ObjectNode> install(ObjectNode authority, byte[] rawCapability);
    }
    private AnonymousBridge() { }

    public static void verifyExecutable(Path executable, String expectedSha256) {
        verifyExecutable(executable, expectedSha256, () -> { });
    }
    private static void verifyExecutable(Path executable, String expectedSha256, Runnable checkpoint) {
        checkpoint.run();
        if (!executable.isAbsolute() || !expectedSha256.matches("[a-f0-9]{64}")) {
            throw new ContractException("BRIDGE_SETUP_INVALID", "An exact approved executable is required");
        }
        try {
            Path normalized = executable.normalize();
            if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS) || !normalized.equals(normalized.toRealPath())) {
                throw new ContractException("BRIDGE_SOURCE_UNAPPROVED", "The approved executable must be an ordinary absolute file");
            }
            long length = Files.size(normalized);
            if (length <= 0 || length > 128L * 1024 * 1024) throw new ContractException("BRIDGE_SOURCE_LIMIT", "Executable exceeds the source byte limit");
            MessageDigest digest = MessageDigest.getInstance("SHA-256"); long count = 0;
            try (var input = Files.newInputStream(normalized)) {
                byte[] buffer = new byte[32 * 1024]; int read;
                while (true) {
                    checkpoint.run(); read = input.read(buffer); checkpoint.run();
                    if (read < 0) break;
                    count += read; if (count > length) throw new IOException(); digest.update(buffer, 0, read);
                }
            }
            if (count != length || length != Files.size(normalized) || !expectedSha256.equals(HexFormat.of().formatHex(digest.digest()))) {
                throw new ContractException("BRIDGE_SOURCE_UNAPPROVED", "Executable source does not match the approved digest");
            }
            checkpoint.run();
        } catch (IOException exception) { throw new ContractException("BRIDGE_SOURCE_UNAPPROVED", "Approved executable source could not be observed"); }
        catch (NoSuchAlgorithmException exception) { throw new AssertionError(exception); }
    }

    /** Caller executes off the game thread. The child is a bounded bridge; the daemon has its own owner. */
    public static ObjectNode exchange(Path executable, String expectedSha256, ObjectNode offer,
                                      byte[] rawCapability, Installer installer) {
        return exchange(Mode.PAIRING, executable, expectedSha256, offer, rawCapability, installer);
    }

    public static ObjectNode exchange(Mode mode, Path executable, String expectedSha256, ObjectNode offer,
                                      byte[] rawCapability, Installer installer) {
        return exchange(mode, executable, expectedSha256, offer, rawCapability, installer, () -> { },
                System.nanoTime() + Duration.ofSeconds(30).toNanos());
    }

    /** 원 요청의 절대 monotonic 기한과 현재성 callback을 재사용한다. 이 overload도 30초 상한을 늘리지 않는다. */
    public static ObjectNode exchange(Mode mode, Path executable, String expectedSha256, ObjectNode offer,
                                      byte[] rawCapability, Installer installer, Runnable originalControl, long originalDeadlineNanos) {
        java.util.Objects.requireNonNull(originalControl);
        long started = System.nanoTime();
        long originalRemaining = Math.min(Duration.ofSeconds(30).toNanos(), originalDeadlineNanos - started);
        if (originalRemaining <= 0) throw failure();
        long until = started + originalRemaining;
        Runnable control = () -> {
            originalControl.run();
            if (until - System.nanoTime() <= 0) throw failure();
        };
        control.run();
        if (rawCapability.length != 32) throw new IllegalArgumentException("Capability must contain 32 bytes");
        envelope(offer, mode.offerKind, offer.path("nonce").asText());
        boolean calibration = mode == Mode.APPLY_APPROVAL && "numeric_calibration_normative47/1".equals(offer.path("purpose").asText());
        if (offer.has("purpose") && !calibration) throw failure();
        if (!offer.path("nonce").isTextual() || !offer.path("nonce").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw failure();
        ObjectNode immutableOffer = offer.deepCopy();
        verifyExecutable(executable, expectedSha256, control);
        control.run();
        byte[] ownedCapability = rawCapability.clone();
        Process process = null;
        var watchdog = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "mmmm-host-bridge-deadline"); thread.setDaemon(true); return thread;
        });
        var drains = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "mmmm-host-bridge-stderr"); thread.setDaemon(true); return thread;
        });
        AtomicBoolean overflow = new AtomicBoolean();
        Throwable originalFailure = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(executable.toString(), "host-bridge", mode.argument);
            // No bearer or secret is placed in process arguments or environment.
            control.run(); process = builder.start(); Process child = process;
            var timer = watchdog.schedule(() -> {
                overflow.set(true);
                try { child.getInputStream().close(); child.getOutputStream().close(); child.getErrorStream().close(); }
                catch (IOException exception) { /* The deadline already makes the handshake fail closed. */ }
                terminateOwned(child);
            }, Math.max(1, until - System.nanoTime()), TimeUnit.NANOSECONDS);
            CompletableFuture<Void> stderr = CompletableFuture.runAsync(() -> {
                try (var input = child.getErrorStream()) {
                    byte[] buffer = new byte[4096]; int read; int count = 0;
                    while ((read = input.read(buffer)) >= 0) {
                        count += read;
                        if (count > 64 * 1024) { overflow.set(true); terminateOwned(child); break; }
                    }
                    Arrays.fill(buffer, (byte) 0);
                } catch (IOException exception) { if (child.isAlive()) overflow.set(true); }
            }, drains);
            try (var input = new DataInputStream(child.getInputStream())) {
                var output = new DataOutputStream(child.getOutputStream());
                Throwable frameFailure = null;
                try {
                control.run(); output.write("MMMMHST1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                write(output, immutableOffer); output.write(ownedCapability); output.flush(); Arrays.fill(ownedCapability, (byte) 0);
                control.run();
                ObjectNode authority = read(input); envelope(authority, mode.authorityKind, immutableOffer.path("nonce").asText());
                control.run();
                byte[] installCapability = rawCapability.clone();
                ObjectNode installed;
                try { installed = installer.install(authority.deepCopy(), installCapability).toCompletableFuture()
                        .get(remaining(until), TimeUnit.NANOSECONDS); }
                finally { Arrays.fill(installCapability, (byte) 0); }
                control.run();
                envelope(installed, calibration ? "host_apply_approval_installed" : "host_pairing_installed", immutableOffer.path("nonce").asText());
                if (calibration && (!immutableOffer.path("purpose").equals(installed.path("purpose"))
                        || !installed.path("selectionDigest").asText().matches("[a-f0-9]{64}")
                        || !installed.path("manifestDigest").asText().matches("[a-f0-9]{64}"))) throw failure();
                write(output, installed);
                ObjectNode completed = read(input); envelope(completed, calibration ? "host_apply_approval_complete" : "host_pairing_complete", immutableOffer.path("nonce").asText());
                if (calibration && (!installed.path("purpose").equals(completed.path("purpose"))
                        || !installed.path("selectionDigest").equals(completed.path("selectionDigest"))
                        || !installed.path("manifestDigest").equals(completed.path("manifestDigest")))) throw failure();
                control.run();
                if (!completed.path("ready").isBoolean() || !completed.path("ready").asBoolean()) throw failure();
                output.close();
                if (input.read() != -1 || !child.waitFor(remaining(until), TimeUnit.NANOSECONDS) || child.exitValue() != 0) throw failure();
                stderr.get(remaining(until), TimeUnit.NANOSECONDS);
                if (overflow.get()) throw failure();
                control.run(); timer.cancel(false); return completed.deepCopy();
                } catch (IOException | InterruptedException | java.util.concurrent.ExecutionException
                         | java.util.concurrent.TimeoutException | RuntimeException | Error failure) {
                    frameFailure = failure; throw failure;
                } finally { closeOutput(output, frameFailure); }
            }
        } catch (IOException | java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException exception) {
            ContractException failed = failure(exception); originalFailure = failed; throw failed;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt(); ContractException failed = failure(exception); originalFailure = failed; throw failed;
        } catch (RuntimeException | Error exception) { originalFailure = exception; throw exception; }
        finally {
            Arrays.fill(ownedCapability, (byte) 0);
            try { if (process != null) terminateOwned(process); }
            catch (RuntimeException cleanup) {
                if (originalFailure != null && cleanup != originalFailure) originalFailure.addSuppressed(cleanup); else throw cleanup;
            } finally { watchdog.shutdownNow(); drains.shutdownNow(); }
        }
    }
    /** Closing an owned output must not replace the original install/current failure. */
    static void closeOutput(DataOutputStream output, Throwable original) throws IOException {
        try { output.close(); }
        catch (IOException | RuntimeException | Error failure) {
            if (original == null) throw failure;
            if (failure != original) original.addSuppressed(failure);
        }
    }
    private static long remaining(long until) throws java.util.concurrent.TimeoutException {
        long value = until - System.nanoTime(); if (value <= 0) throw new java.util.concurrent.TimeoutException(); return value;
    }
    private static void write(DataOutputStream output, ObjectNode value) throws IOException {
        byte[] bytes = ContractJson.bytes(value);
        if (bytes.length == 0 || bytes.length > MAX_FRAME) throw failure();
        output.writeInt(bytes.length); output.write(bytes); output.flush();
    }
    private static ObjectNode read(DataInputStream input) throws IOException {
        int length = input.readInt(); if (length <= 0 || length > MAX_FRAME) throw failure();
        byte[] bytes = input.readNBytes(length); if (bytes.length != length) throw failure();
        try { return ContractJson.object(ContractJson.parse(bytes)); } finally { Arrays.fill(bytes, (byte) 0); }
    }
    private static void envelope(ObjectNode frame, String kind, String nonce) {
        if (!ContractJson.VERSION.equals(frame.path("protocolVersion").asText()) || !kind.equals(frame.path("kind").asText())
                || !nonce.equals(frame.path("nonce").asText())) throw failure();
    }
    private static ContractException failure() { return new ContractException("HOST_PAIRING_FAILED", "The approved host bridge did not complete its bounded handshake"); }
    private static ContractException failure(Throwable cause) { ContractException failed = failure(); failed.initCause(cause); return failed; }
    private static void terminateOwned(Process child) {
        if (!child.isAlive()) return;
        var owned = child.descendants().toList(); owned.forEach(ProcessHandle::destroy); child.destroy();
        try { child.waitFor(500, TimeUnit.MILLISECONDS); } catch (InterruptedException exception) { Thread.currentThread().interrupt(); }
        owned.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
        if (child.isAlive()) child.destroyForcibly();
        try { if (!child.waitFor(1000, TimeUnit.MILLISECONDS) || owned.stream().anyMatch(ProcessHandle::isAlive)) throw failure(); }
        catch (InterruptedException exception) { Thread.currentThread().interrupt(); throw failure(); }
    }
}
