package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Explicitly paired HTTP/1 RPC endpoint, with finite sockets, readers, queue, body and wait. */
public final class PairedLoopbackServer implements AutoCloseable {
    private final HostSession session;
    private final HostDispatcher dispatcher;
    private final byte[] bearer;
    private final ServerSocket listener;
    private final Thread acceptor;
    private final ThreadPoolExecutor workers;
    private final ScheduledThreadPoolExecutor watchdog;
    private final java.util.Set<Socket> sockets = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile boolean closed;

    public PairedLoopbackServer(HostSession session, HostDispatcher dispatcher, byte[] opaqueAsciiBearer) throws IOException {
        if (opaqueAsciiBearer.length < 43 || opaqueAsciiBearer.length > 128) throw new IllegalArgumentException("Pairing capability length is invalid");
        for (byte unit : opaqueAsciiBearer) {
            if (!(unit >= 'a' && unit <= 'z' || unit >= 'A' && unit <= 'Z' || unit >= '0' && unit <= '9' || unit == '_' || unit == '-')) {
                throw new IllegalArgumentException("Pairing capability encoding is invalid");
            }
        }
        this.session = session; this.dispatcher = dispatcher; bearer = opaqueAsciiBearer.clone();
        listener = new ServerSocket(0, 8, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}));
        listener.setSoTimeout(1000);
        workers = new ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(8), task -> {
            Thread worker = new Thread(task, "mmmm-host-rpc"); worker.setDaemon(true); return worker;
        }, new ThreadPoolExecutor.AbortPolicy());
        watchdog = new ScheduledThreadPoolExecutor(1, task -> {
            Thread worker = new Thread(task, "mmmm-host-deadline"); worker.setDaemon(true); return worker;
        });
        watchdog.setRemoveOnCancelPolicy(true);
        acceptor = new Thread(this::accept, "mmmm-host-accept"); acceptor.setDaemon(true); acceptor.start();
    }

    /** Endpoint only. Credentials are supplied to the trusted Coordinator out of band. */
    public String endpoint() { return "http://127.0.0.1:" + listener.getLocalPort() + "/rpc"; }
    private void accept() {
        while (!closed) {
            try {
                Socket socket = listener.accept();
                if (!socket.getInetAddress().isLoopbackAddress()) { socket.close(); continue; }
                socket.setSoTimeout(2000);
                sockets.add(socket);
                var timer = watchdog.schedule(() -> closeSocket(socket), 125, TimeUnit.SECONDS);
                try { workers.execute(() -> { try { serve(socket); } finally { timer.cancel(false); sockets.remove(socket); } }); }
                catch (RejectedExecutionException exception) { timer.cancel(false); sockets.remove(socket); socket.close(); }
            } catch (java.net.SocketTimeoutException exception) {
                // The bounded accept wait permits independent lifecycle shutdown.
            } catch (IOException exception) {
                if (!closed) close();
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            InputStream input = socket.getInputStream();
            String requestLine = line(input, 1024);
            if (!"POST /rpc HTTP/1.1".equals(requestLine) && !"POST /rpc HTTP/1.0".equals(requestLine)) {
                response(socket, 405, ContractJson.newObject().put("error", "METHOD_NOT_ALLOWED")); return;
            }
            Map<String, String> headers = new HashMap<>();
            int bytes = requestLine.length();
            for (int count = 0; ; count++) {
                String header = line(input, 8192);
                bytes += header.length() + 2;
                if (bytes > 16384 || count > 32) throw new ContractException("HTTP_LIMIT", "HTTP headers exceed their limit");
                if (header.isEmpty()) break;
                int colon = header.indexOf(':');
                if (colon <= 0 || header.charAt(0) == ' ' || header.charAt(0) == '\t') throw new ContractException("HTTP_INVALID", "Malformed HTTP header");
                String name = header.substring(0, colon).toLowerCase(Locale.ROOT);
                if (!name.matches("[a-z0-9-]+") || headers.putIfAbsent(name, header.substring(colon + 1).trim()) != null) {
                    throw new ContractException("HTTP_INVALID", "Duplicate or malformed HTTP header");
                }
            }
            String authorization = headers.getOrDefault("authorization", "");
            byte[] supplied = authorization.startsWith("Bearer ")
                    ? authorization.substring(7).getBytes(StandardCharsets.US_ASCII) : new byte[0];
            boolean authenticated = MessageDigest.isEqual(bearer, supplied);
            Arrays.fill(supplied, (byte) 0);
            if (!authenticated || session.closed()) {
                response(socket, 401, ContractJson.newObject().put("error", "UNAUTHENTICATED")); return;
            }
            if (!session.epoch().equals(headers.get("x-mmmm-epoch"))) {
                response(socket, 409, ContractJson.newObject().put("error", "SESSION_EPOCH_MISMATCH")); return;
            }
            if (headers.containsKey("origin") || headers.containsKey("transfer-encoding")) {
                response(socket, 400, ContractJson.newObject().put("error", "HTTP_UNSUPPORTED")); return;
            }
            String lengthText = headers.getOrDefault("content-length", "");
            if (!lengthText.matches("[1-9][0-9]{0,7}")) throw new ContractException("HTTP_INVALID", "A bounded Content-Length is required");
            int length = Integer.parseInt(lengthText);
            if (length > ContractJson.MAX_BYTES) throw new ContractException("HTTP_LIMIT", "RPC body exceeds its limit");
            byte[] body = input.readNBytes(length);
            if (body.length != length) throw new ContractException("HTTP_INVALID", "RPC body is incomplete");
            ObjectNode envelope = ContractJson.object(ContractJson.parse(body));
            HostDispatcher.exactFields(envelope, java.util.Set.of("jsonrpc", "id", "method", "params"));
            ObjectNode request = ContractJson.object(envelope.get("params"));
            if (!"2.0".equals(envelope.path("jsonrpc").asText()) || !"mmmm.host".equals(envelope.path("method").asText())
                    || !envelope.get("id").isTextual() || !envelope.path("id").asText().equals(request.path("requestId").asText())) {
                throw new ContractException("RPC_INVALID", "Host RPC envelope does not match its contract");
            }
            ObjectNode result = ContractJson.newObject().put("jsonrpc", "2.0");
            result.set("id", envelope.get("id"));
            try {
                long remaining = Duration.between(Instant.now(), Instant.parse(request.path("deadlineAt").asText())).toMillis();
                if (remaining <= 0) throw new TimeoutException();
                JsonNode host = dispatcher.handle(session, request).toCompletableFuture().get(Math.min(remaining, 120_000), TimeUnit.MILLISECONDS);
                result.set("result", host);
            } catch (TimeoutException exception) {
                result.set("error", rpcError("DEADLINE_EXCEEDED", "dispatch".equals(request.path("method").asText()) ? "unknown" : "none_confirmed"));
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                result.set("error", rpcError("HOST_INTERRUPTED", "unknown"));
            } catch (java.util.concurrent.ExecutionException exception) {
                result.set("error", rpcError("HOST_EXECUTION_FAILED", "unknown"));
            } catch (ContractException exception) { result.set("error", rpcError(exception.code(), "none_confirmed")); }
            response(socket, 200, result);
        } catch (IOException | RuntimeException exception) {
            // Unauthenticated or malformed input is closed without echoing any supplied bytes or credentials.
        }
    }

    private static ObjectNode rpcError(String code, String effects) {
        ObjectNode result = ContractJson.newObject().put("code", -32000).put("message", code);
        result.set("data", HostDispatcher.error(code, effects));
        return result;
    }
    private static String line(InputStream input, int maximum) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        boolean carriageReturn = false;
        for (int count = 0; count <= maximum; count++) {
            int unit = input.read();
            if (unit < 0) throw new IOException("Incomplete HTTP header");
            if (carriageReturn) {
                if (unit != '\n') throw new IOException("Malformed HTTP line ending");
                return bytes.toString(StandardCharsets.US_ASCII);
            }
            if (unit == '\r') carriageReturn = true;
            else {
                if (unit < 32 && unit != '\t' || unit > 126) throw new IOException("Non-ASCII HTTP header");
                bytes.write(unit);
            }
        }
        throw new IOException("HTTP line exceeds its limit");
    }
    private static void response(Socket socket, int status, JsonNode value) throws IOException {
        byte[] body = ContractJson.bytes(value);
        byte[] headers = ("HTTP/1.1 " + status + " " + (status == 200 ? "OK" : "Rejected")
                + "\r\nContent-Type: application/json\r\nContent-Length: " + body.length
                + "\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
        socket.getOutputStream().write(headers);
        socket.getOutputStream().write(body);
        socket.getOutputStream().flush();
    }
    @Override public void close() {
        closed = true;
        session.close();
        Arrays.fill(bearer, (byte) 0);
        try { listener.close(); } catch (IOException exception) { /* The listener may already be closed. */ }
        workers.shutdownNow();
        sockets.forEach(PairedLoopbackServer::closeSocket);
        sockets.clear();
        watchdog.shutdownNow();
    }
    private static void closeSocket(Socket socket) {
        try { socket.close(); } catch (IOException exception) { /* Lifecycle cleanup may race with normal completion. */ }
    }
}
