package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.AnonymousBridge;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.network.chat.Component;
import net.minecraft.server.permissions.PermissionLevel;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.builder.RequiredArgumentBuilder;
import com.mojang.brigadier.arguments.StringArgumentType;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit game-admin pairing command; public setup supplies requests, Rust supplies authority. */
final class ManualHostConnection {
    private static final Set<String> PAIRING_READ_PERMISSIONS = Set.of("mmmm:world_read", "mmmm:command_complete", "mmmm:provider_inventory");
    private final MmmmFabricHost host;
    private final ContractJson contracts;
    private final AtomicBoolean connecting = new AtomicBoolean();
    ManualHostConnection(MmmmFabricHost host, ContractJson contracts) { this.host = host; this.contracts = contracts; }
    void register() {
        CommandRegistrationCallback.EVENT.register((dispatcher, registryAccess, selection) -> dispatcher.register(
                LiteralArgumentBuilder.<CommandSourceStack>literal("mmmm")
                        .requires(source -> source.getPermissionContext().permissionLevel() == PermissionLevel.ADMINS)
                        .then(LiteralArgumentBuilder.<CommandSourceStack>literal("connect").executes(command -> {
                            var player = command.getSource().getPlayer();
                            if (player == null || !connecting.compareAndSet(false, true)) return 0;
                            UUID playerId = player.getUUID();
                            var worker = Executors.newSingleThreadExecutor(task -> { Thread thread = new Thread(task, "mmmm-host-pairing"); thread.setDaemon(true); return thread; });
                            CompletableFuture.runAsync(() -> connect(playerId), worker).whenComplete((value, failure) -> {
                                connecting.set(false); worker.shutdown();
                                host.gameTask(() -> {
                                    var current = host.pairedCandidate(playerId);
                                    if (current != null) current.sendSystemMessage(Component.literal(failure == null
                                            ? "MMMM host pairing completed" : "MMMM host pairing failed; check the public setup and coordinator state"));
                                });
                            });
                            return 1;
                        }))
                        .then(LiteralArgumentBuilder.<CommandSourceStack>literal("approve")
                                .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("planId", StringArgumentType.word())
                                        .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("planHash", StringArgumentType.word()).executes(command -> {
                                            var player = command.getSource().getPlayer();
                                            if (player == null || !connecting.compareAndSet(false, true)) return 0;
                                            UUID playerId = player.getUUID();
                                            String planId = StringArgumentType.getString(command, "planId"); String planHash = StringArgumentType.getString(command, "planHash");
                                            var worker = Executors.newSingleThreadExecutor(task -> { Thread thread = new Thread(task, "mmmm-plan-approval"); thread.setDaemon(true); return thread; });
                                            CompletableFuture.runAsync(() -> approve(playerId, planId, planHash), worker).whenComplete((value, failure) -> {
                                                connecting.set(false); worker.shutdown();
                                                host.gameTask(() -> {
                                                    var current = host.pairedCandidate(playerId);
                                                    if (current != null) current.sendSystemMessage(Component.literal(failure == null
                                                            ? "MMMM plan approval installed" : "MMMM plan approval failed; the frozen plan, current policy and runtime evidence must match"));
                                                });
                                            }); return 1;
                                        }))))));
    }

    private void approve(UUID playerId, String planId, String planHash) {
        byte[] raw = new byte[32]; new SecureRandom().nextBytes(raw); AtomicBoolean cancelled = new AtomicBoolean();
        java.util.concurrent.atomic.AtomicReference<String> installedEndpoint = new java.util.concurrent.atomic.AtomicReference<>();
        try {
            HostSetup setup = HostSetup.read(contracts, FabricLoader.getInstance().getGameDir().resolve("config/mmmm-host.json"));
            ObjectNode offer = host.gameTask(() -> host.approvalOffer(playerId, setup, planId, planHash)).toCompletableFuture().join();
            ObjectNode completed = AnonymousBridge.exchange(AnonymousBridge.Mode.APPLY_APPROVAL, setup.executable(), setup.executableSha256(), offer, raw, (authority, capability) -> {
                String expectedCapabilityDigest = ContractJson.sha256(capability);
                return host.gameTask(() -> {
                    if (cancelled.get()) throw new ContractException("HOST_PAIRING_CANCELLED", "Approval bridge lifetime ended");
                    byte[] privateCapability = capability.clone();
                    try {
                        if (!expectedCapabilityDigest.equals(ContractJson.sha256(privateCapability))) throw new ContractException("HOST_PAIRING_CANCELLED", "Approval capability lifetime ended before installation");
                        byte[] bearer = HexFormat.of().formatHex(privateCapability).getBytes(StandardCharsets.US_ASCII);
                        String installed;
                        try { installed = host.installApproval(playerId, offer, authority, bearer); }
                        catch (java.io.IOException exception) { throw new ContractException("HOST_PAIRING_FAILED", "The immutable approval listener could not be started"); }
                        finally { Arrays.fill(bearer, (byte) 0); }
                        installedEndpoint.set(installed);
                        if (cancelled.get()) { host.revokeApproval(installed); throw new ContractException("HOST_PAIRING_CANCELLED", "Approval bridge ended during activation"); }
                        var uri = java.net.URI.create(installed);
                        ObjectNode frame = ContractJson.newObject().put("kind", "host_pairing_installed").put("protocolVersion", ContractJson.VERSION)
                                .put("nonce", offer.path("nonce").asText());
                        frame.putObject("hostEndpoint").put("address", "127.0.0.1:" + uri.getPort()).put("path", "/rpc")
                                .put("hostEpoch", offer.path("hostHello").path("environment").path("sessionEpoch").asText()); return frame;
                    } finally { Arrays.fill(privateCapability, (byte) 0); }
                });
            });
            HostDispatcher.exactFields(completed, Set.of("kind", "protocolVersion", "nonce", "ready", "coordinatorEpoch", "hostEpoch", "contextId"));
            if (!offer.path("hostHello").path("environment").path("sessionEpoch").equals(completed.path("hostEpoch"))
                    || !completed.path("coordinatorEpoch").isTextual() || !completed.path("coordinatorEpoch").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid();
            boolean contextMatched = false; for (JsonNode id : offer.path("contextIds")) contextMatched |= id.equals(completed.path("contextId"));
            if (!contextMatched) throw invalid();
        } catch (RuntimeException exception) { cancelled.set(true); host.revokeApproval(installedEndpoint.get()); throw exception; }
        finally { Arrays.fill(raw, (byte) 0); }
    }

    private void connect(UUID playerId) {
        byte[] raw = new byte[32]; new SecureRandom().nextBytes(raw);
        AtomicBoolean cancelled = new AtomicBoolean();
        java.util.concurrent.atomic.AtomicReference<String> installedEpoch = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Set<String>> installedContexts = new java.util.concurrent.atomic.AtomicReference<>(Set.of());
        try {
            HostSetup setup = HostSetup.read(contracts, FabricLoader.getInstance().getGameDir().resolve("config/mmmm-host.json"));
            ObjectNode offer = host.gameTask(() -> host.pairingOffer(playerId, setup)).toCompletableFuture()
                    .orTimeout(10, java.util.concurrent.TimeUnit.SECONDS).join();
            ObjectNode completed = AnonymousBridge.exchange(setup.executable(), setup.executableSha256(), offer, raw, (authority, capability) -> {
                    String expectedCapabilityDigest = ContractJson.sha256(capability);
                    return host.gameTask(() -> {
                        if (cancelled.get()) throw new ContractException("HOST_PAIRING_CANCELLED", "Pairing generation was cancelled");
                        byte[] privateCapability = capability.clone();
                        if (!expectedCapabilityDigest.equals(ContractJson.sha256(privateCapability))) {
                            Arrays.fill(privateCapability, (byte) 0); throw new ContractException("HOST_PAIRING_CANCELLED", "Pairing capability lifetime ended before installation");
                        }
                        try {
                        validateAuthority(offer, setup, authority);
                        var player = host.pairedCandidate(playerId);
                        if (player == null || player.createCommandSourceStack().getPermissionContext().permissionLevel() != PermissionLevel.ADMINS) {
                            throw new ContractException("PERMISSION_DENIED", "Actual paired player administrator permission ended");
                        }
                        var contexts = new ArrayList<ObjectNode>(); authority.path("contexts").forEach(value -> contexts.add(ContractJson.object(value).deepCopy()));
                        Set<String> contextIds = new HashSet<>(); contexts.forEach(value -> contextIds.add(value.path("contextId").asText())); installedContexts.set(Set.copyOf(contextIds));
                        var sources = new HashMap<String, String>(); authority.path("approvedSources").fields().forEachRemaining(entry -> sources.put(entry.getKey(), entry.getValue().asText()));
                        var actions = new HashSet<String>(); authority.path("approvedActions").forEach(value -> actions.add(value.asText()));
                        var permissions = new HashSet<String>(); authority.path("permissions").forEach(value -> permissions.add(value.asText()));
                        byte[] bearer = HexFormat.of().formatHex(privateCapability).getBytes(StandardCharsets.US_ASCII);
                        Arrays.fill(privateCapability, (byte) 0);
                        String endpoint;
                        if (cancelled.get()) { Arrays.fill(bearer, (byte) 0); throw new ContractException("HOST_PAIRING_CANCELLED", "Pairing generation ended before listener activation"); }
                        String epoch = offer.path("hostHello").path("environment").path("sessionEpoch").asText(); installedEpoch.set(epoch);
                        try { endpoint = host.install(playerId, offer.path("principalId").asText(), bearer, permissions, contexts, sources, actions, false); }
                        catch (java.io.IOException exception) { throw new ContractException("HOST_PAIRING_FAILED", "The paired loopback listener could not be started"); }
                        finally { Arrays.fill(bearer, (byte) 0); }
                        if (cancelled.get()) { host.revokePairing(epoch); throw new ContractException("HOST_PAIRING_CANCELLED", "Pairing generation ended during listener activation"); }
                        ObjectNode installed = ContractJson.newObject().put("kind", "host_pairing_installed").put("protocolVersion", ContractJson.VERSION)
                                .put("nonce", offer.path("nonce").asText());
                        var uri = java.net.URI.create(endpoint);
                        installed.putObject("hostEndpoint").put("address", "127.0.0.1:" + uri.getPort()).put("path", "/rpc").put("hostEpoch", epoch);
                        return installed;
                        } finally { Arrays.fill(privateCapability, (byte) 0); }
                    }); });
            HostDispatcher.exactFields(completed, Set.of("kind", "protocolVersion", "nonce", "ready", "coordinatorEpoch", "hostEpoch", "contextId"));
            if (!completed.path("hostEpoch").asText().equals(installedEpoch.get())) throw new ContractException("SESSION_EPOCH_MISMATCH", "Pairing completion belongs to another host generation");
            if (!installedContexts.get().contains(completed.path("contextId").asText()) || !completed.path("coordinatorEpoch").isTextual()
                    || !completed.path("coordinatorEpoch").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid();
        } catch (RuntimeException exception) {
            cancelled.set(true); host.revokePairing(installedEpoch.get()); throw exception;
        } finally { Arrays.fill(raw, (byte) 0); }
    }
    private void validateAuthority(ObjectNode offer, HostSetup setup, ObjectNode authority) {
        HostDispatcher.exactFields(authority, Set.of("kind", "protocolVersion", "nonce", "contexts", "approvedSources", "approvedActions", "permissions", "writeProfileVerified"));
        if (!authority.path("writeProfileVerified").isBoolean() || authority.path("writeProfileVerified").asBoolean()
                || !authority.path("contexts").isArray() || authority.path("contexts").isEmpty() || authority.path("contexts").size() > 16
                || !authority.path("approvedSources").isObject() || !authority.path("approvedActions").isArray() || !authority.path("permissions").isArray()) throw invalid();
        for (JsonNode permission : authority.path("permissions")) if (!permission.isTextual() || !PAIRING_READ_PERMISSIONS.contains(permission.asText())) throw invalid();
        for (JsonNode context : authority.path("contexts")) {
            contracts.validate("ExecutionContext", context);
            if (!ContractJson.contextDigest(ContractJson.object(context)).equals(context.path("contextDigest").asText())
                    || !offer.path("principalId").asText().equals(context.path("principalRef").asText())
                    || !setup.projectId().equals(context.path("projectId").asText()) || !offer.path("hostHello").path("environment").equals(context.path("environment"))) throw invalid();
            ObjectNode expectedScope = setup.scope();
            expectedScope.withArray("regions").forEach(region -> {
                ObjectNode value = ContractJson.object(region); value.put("contextId", context.path("contextId").asText());
                value.put("worldId", context.path("environment").path("worldId").asText());
            });
            if (!scopeSubset(expectedScope, context.path("scope"))) throw invalid();
            ObjectNode player = ContractJson.object(offer.path("playerContext"));
            for (String field : Set.of("dimension", "executorHandle", "origin", "rotationDegrees", "anchor")) {
                if (!ContractJson.digest(player.path(field)).equals(ContractJson.digest(context.path(field)))) throw invalid();
            }
        }
        if (authority.path("approvedSources").size() != 1
                || !setup.hostArtifactDigest().equals(authority.path("approvedSources").path("mmmm_host").asText())) throw invalid();
        Set<String> expected = new HashSet<>(); offer.path("nativeActions").forEach(action -> expected.add(ContractJson.digest(action)));
        Set<String> approved = new HashSet<>(); for (JsonNode action : authority.path("approvedActions")) {
            if (!action.isTextual() || !expected.contains(action.asText()) || !approved.add(action.asText())) throw invalid();
        }
        if (!expected.equals(approved)) throw invalid();
    }
    private static boolean scopeSubset(ObjectNode requested, JsonNode actual) {
        if (!requested.path("projectId").equals(actual.path("projectId"))) return false;
        for (String field : Set.of("resourceIds", "objectIds", "externalTargetIds")) {
            Set<String> allowed = new HashSet<>(); requested.path(field).forEach(value -> allowed.add(value.asText()));
            for (JsonNode value : actual.path(field)) if (!allowed.contains(value.asText())) return false;
        }
        for (JsonNode region : actual.path("regions")) {
            boolean contained = false;
            for (JsonNode allowed : requested.path("regions")) {
                if (!allowed.path("dimension").equals(region.path("dimension")) || !allowed.path("contextId").equals(region.path("contextId"))
                        || !allowed.path("worldId").equals(region.path("worldId"))) continue;
                boolean bounds = true;
                for (int axis = 0; axis < 3; axis++) {
                    var min = region.path("min").get(axis).bigIntegerValue(); var max = region.path("maxExclusive").get(axis).bigIntegerValue();
                    bounds &= min.compareTo(max) < 0 && min.compareTo(allowed.path("min").get(axis).bigIntegerValue()) >= 0
                            && max.compareTo(allowed.path("maxExclusive").get(axis).bigIntegerValue()) <= 0;
                }
                if (bounds) { contained = true; break; }
            }
            if (!contained) return false;
        }
        return true;
    }
    private static ContractException invalid() { return new ContractException("HOST_AUTHORITY_INVALID", "Rust authority reply does not match the actual host and approved setup request"); }
}
