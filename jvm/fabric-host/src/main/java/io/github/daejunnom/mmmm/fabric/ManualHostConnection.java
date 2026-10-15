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
import java.util.List;
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
                                        }))))
                        .then(calibrationCommand())
                        .then(bootstrapCommand())));
    }

    private LiteralArgumentBuilder<CommandSourceStack> calibrationCommand() {
        return LiteralArgumentBuilder.<CommandSourceStack>literal("calibration")
                .then(LiteralArgumentBuilder.<CommandSourceStack>literal("approve")
                        .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("planId", StringArgumentType.word())
                                .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("planHash", StringArgumentType.word()).executes(command -> {
                                    var player = command.getSource().getPlayer();
                                    if (player == null || !connecting.compareAndSet(false, true)) return 0;
                                    UUID playerId = player.getUUID(); String planId = StringArgumentType.getString(command, "planId");
                                    String planHash = StringArgumentType.getString(command, "planHash");
                                    var worker = Executors.newSingleThreadExecutor(task -> { Thread thread = new Thread(task, "mmmm-calibration-approval"); thread.setDaemon(true); return thread; });
                                    CompletableFuture.runAsync(() -> approveCalibration(playerId, planId, planHash), worker).whenComplete((value, failure) -> {
                                        connecting.set(false); worker.shutdown();
                                        host.gameTask(() -> {
                                            var current = host.pairedCandidate(playerId);
                                            if (current != null) current.sendSystemMessage(Component.literal(failure == null
                                                    ? "MMMM calibration 목적 승인을 설치했습니다; 실행 준비는 별도로 검사합니다"
                                                    : "MMMM calibration 승인에 실패했습니다; 원 plan과 현재 권한을 확인하세요"));
                                        });
                                    }); return 1;
                                }))));
    }

    private LiteralArgumentBuilder<CommandSourceStack> bootstrapCommand() {
        return LiteralArgumentBuilder.<CommandSourceStack>literal("calibration-bootstrap")
                .then(LiteralArgumentBuilder.<CommandSourceStack>literal("approve")
                        .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("planId", StringArgumentType.word())
                                .then(RequiredArgumentBuilder.<CommandSourceStack, String>argument("planHash", StringArgumentType.word()).executes(command -> {
                                    var player = command.getSource().getPlayer();
                                    if (player == null || !connecting.compareAndSet(false, true)) return 0;
                                    UUID playerId = player.getUUID(); String planId = StringArgumentType.getString(command, "planId");
                                    String planHash = StringArgumentType.getString(command, "planHash");
                                    var worker = Executors.newSingleThreadExecutor(task -> { Thread thread = new Thread(task, "mmmm-bootstrap-approval"); thread.setDaemon(true); return thread; });
                                    CompletableFuture.runAsync(() -> approveBootstrap(playerId, planId, planHash), worker).whenComplete((value, failure) -> {
                                        connecting.set(false); worker.shutdown();
                                        host.gameTask(() -> {
                                            var current = host.pairedCandidate(playerId);
                                            if (current != null) current.sendSystemMessage(Component.literal(failure == null
                                                    ? "MMMM bootstrap 목적 승인을 설치했습니다; 실행 준비는 별도로 검사합니다"
                                                    : "MMMM bootstrap 승인에 실패했습니다; 원 plan과 현재 권한을 확인하세요"));
                                        });
                                    }); return 1;
                                }))));
    }

    private void approveBootstrap(UUID playerId, String planId, String planHash) {
        long started = System.nanoTime(), until = started + java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
        byte[] raw = new byte[32]; new SecureRandom().nextBytes(raw); AtomicBoolean cancelled = new AtomicBoolean();
        Runnable control = () -> {
            if (cancelled.get() || Thread.currentThread().isInterrupted()) throw new ContractException("HOST_PAIRING_CANCELLED", "원 bootstrap 승인 요청이 끝났습니다");
            if (until - System.nanoTime() <= 0) throw new ContractException("HOST_PAIRING_TIMEOUT", "원 bootstrap 승인 기한이 끝났습니다");
        };
        var installedEndpoint = new java.util.concurrent.atomic.AtomicReference<String>();
        var nonce = new java.util.concurrent.atomic.AtomicReference<String>();
        var installedSelection = new java.util.concurrent.atomic.AtomicReference<String>();
        var installedManifest = new java.util.concurrent.atomic.AtomicReference<String>();
        try {
            control.run(); HostSetup setup = HostSetup.read(contracts, FabricLoader.getInstance().getGameDir().resolve("config/mmmm-host.json")); control.run();
            ObjectNode offer = host.gameTask(() -> {
                control.run(); ObjectNode actual = host.bootstrapApprovalOffer(playerId, setup, planId, planHash, control, until);
                nonce.set(actual.path("nonce").asText()); control.run(); return actual;
            }).toCompletableFuture().orTimeout(Math.max(1, Math.min(java.util.concurrent.TimeUnit.SECONDS.toNanos(10), until - System.nanoTime())), java.util.concurrent.TimeUnit.NANOSECONDS).join();
            control.run();
            ObjectNode completed = AnonymousBridge.exchange(AnonymousBridge.Mode.APPLY_APPROVAL, setup.executable(), setup.executableSha256(), offer, raw,
                    (authority, capability) -> {
                        control.run(); String expectedCapabilityDigest = ContractJson.sha256(capability);
                        return host.gameTask(() -> {
                            control.run(); byte[] privateCapability = capability.clone();
                            try {
                                if (!expectedCapabilityDigest.equals(ContractJson.sha256(privateCapability))) throw new ContractException("HOST_PAIRING_CANCELLED", "원 bootstrap capability 수명이 끝났습니다");
                                byte[] bearer = HexFormat.of().formatHex(privateCapability).getBytes(StandardCharsets.US_ASCII);
                                String installed;
                                try { installed = host.installBootstrapApproval(playerId, offer, authority, bearer, control); }
                                catch (java.io.IOException exception) {
                                    ContractException typed = new ContractException("HOST_PAIRING_FAILED", "Bootstrap 목적 listener를 설치하지 못했습니다");
                                    typed.initCause(exception); throw typed;
                                }
                                finally { Arrays.fill(bearer, (byte) 0); }
                                installedEndpoint.set(installed); control.run();
                                ObjectNode manifest = ContractJson.object(authority.path("manifest"));
                                installedSelection.set(manifest.path("selectionDigest").asText()); installedManifest.set(ContractJson.digest(manifest));
                                var uri = java.net.URI.create(installed);
                                ObjectNode frame = ContractJson.newObject().put("kind", "host_apply_approval_installed").put("protocolVersion", ContractJson.VERSION)
                                        .put("nonce", offer.path("nonce").asText()).put("purpose", NativeCalibrationBootstrap.PURPOSE)
                                        .put("selectionDigest", installedSelection.get()).put("manifestDigest", installedManifest.get());
                                frame.putObject("hostEndpoint").put("address", "127.0.0.1:" + uri.getPort()).put("path", "/rpc")
                                        .put("hostEpoch", offer.path("hostHello").path("environment").path("sessionEpoch").asText());
                                control.run(); return frame;
                            } catch (RuntimeException failure) { host.revokeApproval(installedEndpoint.get()); throw failure; }
                            finally { Arrays.fill(privateCapability, (byte) 0); }
                        });
                    }, control, until);
            control.run(); validateBootstrapCompletion(offer, completed, installedSelection.get(), installedManifest.get()); control.run();
            host.gameTask(() -> host.confirmBootstrapApproval(installedEndpoint.get(), offer, installedSelection.get(), installedManifest.get(), control))
                    .toCompletableFuture().orTimeout(Math.max(1, Math.min(java.util.concurrent.TimeUnit.SECONDS.toNanos(10), until - System.nanoTime())), java.util.concurrent.TimeUnit.NANOSECONDS).join();
            control.run();
        } catch (RuntimeException failure) { cancelled.set(true); host.revokeApproval(installedEndpoint.get()); throw failure; }
        finally { host.releaseBootstrapOffer(nonce.get()); Arrays.fill(raw, (byte) 0); }
    }

    static void validateBootstrapCompletion(ObjectNode offer, ObjectNode completed, String selectionDigest, String manifestDigest) {
        HostDispatcher.exactFields(completed, Set.of("kind", "protocolVersion", "nonce", "ready", "coordinatorEpoch", "hostEpoch", "contextId", "purpose", "selectionDigest", "manifestDigest"));
        if (!"host_apply_approval_complete".equals(completed.path("kind").asText()) || !ContractJson.VERSION.equals(completed.path("protocolVersion").asText())
                || !offer.path("nonce").equals(completed.path("nonce")) || !NativeCalibrationBootstrap.PURPOSE.equals(completed.path("purpose").asText())
                || !NativeCalibrationBootstrap.PURPOSE.equals(offer.path("purpose").asText())
                || !completed.path("ready").isBoolean() || !completed.path("ready").asBoolean()
                || selectionDigest == null || manifestDigest == null || !selectionDigest.matches("[a-f0-9]{64}") || !manifestDigest.matches("[a-f0-9]{64}")
                || !completed.path("selectionDigest").isTextual() || !completed.path("manifestDigest").isTextual()
                || !selectionDigest.equals(completed.path("selectionDigest").asText())
                || !manifestDigest.equals(completed.path("manifestDigest").asText())
                || !offer.path("hostHello").path("environment").path("sessionEpoch").equals(completed.path("hostEpoch"))
                || !completed.path("coordinatorEpoch").isTextual() || !completed.path("coordinatorEpoch").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid();
        boolean context = false; for (JsonNode id : offer.path("contextIds")) context |= id.equals(completed.path("contextId"));
        if (!context) throw invalid();
    }

    private void approveCalibration(UUID playerId, String planId, String planHash) {
        long started = System.nanoTime(), until = started + java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
        byte[] raw = new byte[32]; new SecureRandom().nextBytes(raw); AtomicBoolean cancelled = new AtomicBoolean();
        Runnable control = () -> {
            if (cancelled.get() || Thread.currentThread().isInterrupted()) throw new ContractException("HOST_PAIRING_CANCELLED", "원 calibration 승인 요청이 끝났습니다");
            if (until - System.nanoTime() <= 0) throw new ContractException("HOST_PAIRING_TIMEOUT", "원 calibration 승인 기한이 끝났습니다");
        };
        var installedEndpoint = new java.util.concurrent.atomic.AtomicReference<String>();
        var nonce = new java.util.concurrent.atomic.AtomicReference<String>();
        var installedSelection = new java.util.concurrent.atomic.AtomicReference<String>();
        var installedManifest = new java.util.concurrent.atomic.AtomicReference<String>();
        try {
            control.run(); HostSetup setup = HostSetup.read(contracts, FabricLoader.getInstance().getGameDir().resolve("config/mmmm-host.json")); control.run();
            ObjectNode offer = host.gameTask(() -> {
                control.run(); ObjectNode actual = host.calibrationApprovalOffer(playerId, setup, planId, planHash, control, until);
                nonce.set(actual.path("nonce").asText()); control.run(); return actual;
            }).toCompletableFuture().orTimeout(Math.max(1, Math.min(java.util.concurrent.TimeUnit.SECONDS.toNanos(10), until - System.nanoTime())), java.util.concurrent.TimeUnit.NANOSECONDS).join();
            control.run();
            ObjectNode completed = AnonymousBridge.exchange(AnonymousBridge.Mode.APPLY_APPROVAL, setup.executable(), setup.executableSha256(), offer, raw,
                    (authority, capability) -> {
                        control.run(); String expectedCapabilityDigest = ContractJson.sha256(capability);
                        return host.gameTask(() -> {
                            control.run(); byte[] privateCapability = capability.clone();
                            try {
                                if (!expectedCapabilityDigest.equals(ContractJson.sha256(privateCapability))) throw new ContractException("HOST_PAIRING_CANCELLED", "원 calibration capability 수명이 끝났습니다");
                                byte[] bearer = HexFormat.of().formatHex(privateCapability).getBytes(StandardCharsets.US_ASCII);
                                String installed;
                                try { installed = host.installCalibrationApproval(playerId, offer, authority, bearer, control); }
                                catch (java.io.IOException exception) { throw new ContractException("HOST_PAIRING_FAILED", "Calibration 목적 listener를 설치하지 못했습니다"); }
                                finally { Arrays.fill(bearer, (byte) 0); }
                                installedEndpoint.set(installed); control.run();
                                ObjectNode manifest = ContractJson.object(authority.path("manifest"));
                                installedSelection.set(manifest.path("selectionDigest").asText()); installedManifest.set(ContractJson.digest(manifest));
                                var uri = java.net.URI.create(installed);
                                ObjectNode frame = ContractJson.newObject().put("kind", "host_apply_approval_installed").put("protocolVersion", ContractJson.VERSION)
                                        .put("nonce", offer.path("nonce").asText()).put("purpose", NativeCalibrationApproval.PURPOSE)
                                        .put("selectionDigest", installedSelection.get()).put("manifestDigest", installedManifest.get());
                                frame.putObject("hostEndpoint").put("address", "127.0.0.1:" + uri.getPort()).put("path", "/rpc")
                                        .put("hostEpoch", offer.path("hostHello").path("environment").path("sessionEpoch").asText());
                                control.run(); return frame;
                            } catch (RuntimeException failure) { host.revokeApproval(installedEndpoint.get()); throw failure; }
                            finally { Arrays.fill(privateCapability, (byte) 0); }
                        });
                    }, control, until);
            control.run(); validateCalibrationCompletion(offer, completed, installedSelection.get(), installedManifest.get()); control.run();
            host.gameTask(() -> host.confirmCalibrationApproval(installedEndpoint.get(), offer, installedSelection.get(), installedManifest.get(), control))
                    .toCompletableFuture().orTimeout(Math.max(1, Math.min(java.util.concurrent.TimeUnit.SECONDS.toNanos(10), until - System.nanoTime())), java.util.concurrent.TimeUnit.NANOSECONDS).join();
            control.run();
        } catch (RuntimeException failure) { cancelled.set(true); host.revokeApproval(installedEndpoint.get()); throw failure; }
        finally { host.releaseCalibrationOffer(nonce.get()); Arrays.fill(raw, (byte) 0); }
    }

    static void validateCalibrationCompletion(ObjectNode offer, ObjectNode completed, String selectionDigest, String manifestDigest) {
        HostDispatcher.exactFields(completed, Set.of("kind", "protocolVersion", "nonce", "ready", "coordinatorEpoch", "hostEpoch", "contextId", "purpose", "selectionDigest", "manifestDigest"));
        if (!"host_apply_approval_complete".equals(completed.path("kind").asText()) || !ContractJson.VERSION.equals(completed.path("protocolVersion").asText())
                || !offer.path("nonce").equals(completed.path("nonce")) || !NativeCalibrationApproval.PURPOSE.equals(completed.path("purpose").asText())
                || !completed.path("ready").isBoolean() || !completed.path("ready").asBoolean()
                || selectionDigest == null || manifestDigest == null || !selectionDigest.matches("[a-f0-9]{64}") || !manifestDigest.matches("[a-f0-9]{64}")
                || !completed.path("selectionDigest").isTextual() || !completed.path("manifestDigest").isTextual()
                || !selectionDigest.equals(completed.path("selectionDigest").asText())
                || !manifestDigest.equals(completed.path("manifestDigest").asText())
                || !offer.path("hostHello").path("environment").path("sessionEpoch").equals(completed.path("hostEpoch"))
                || !completed.path("coordinatorEpoch").isTextual() || !completed.path("coordinatorEpoch").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid();
        boolean context = false; for (JsonNode id : offer.path("contextIds")) context |= id.equals(completed.path("contextId"));
        if (!context) throw invalid();
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
        long connectStarted = System.nanoTime();
        byte[] raw = new byte[32]; new SecureRandom().nextBytes(raw);
        AtomicBoolean cancelled = new AtomicBoolean();
        Runnable pairingControl = () -> {
            if (cancelled.get()) throw new ContractException("HOST_PAIRING_CANCELLED", "Original pairing generation was cancelled");
            if (System.nanoTime() - connectStarted >= java.util.concurrent.TimeUnit.SECONDS.toNanos(30)) {
                cancelled.set(true); throw new ContractException("HOST_PAIRING_TIMEOUT", "Original pairing lifetime expired");
            }
        };
        java.util.concurrent.atomic.AtomicReference<String> installedEpoch = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Set<String>> installedContexts = new java.util.concurrent.atomic.AtomicReference<>(Set.of());
        try {
            pairingControl.run();
            HostSetup setup = HostSetup.read(contracts, FabricLoader.getInstance().getGameDir().resolve("config/mmmm-host.json"));
            pairingControl.run();
            long offerRemaining = java.util.concurrent.TimeUnit.SECONDS.toNanos(30) - (System.nanoTime() - connectStarted);
            pairingControl.run();
            ObjectNode offer = host.gameTask(() -> {
                pairingControl.run(); ObjectNode offered = host.pairingOffer(playerId, setup); pairingControl.run(); return offered;
            }).toCompletableFuture().orTimeout(Math.min(java.util.concurrent.TimeUnit.SECONDS.toNanos(10), offerRemaining),
                    java.util.concurrent.TimeUnit.NANOSECONDS).join();
            pairingControl.run();
            ObjectNode completed = AnonymousBridge.exchange(setup.executable(), setup.executableSha256(), offer, raw, (authority, capability) -> {
                    pairingControl.run();
                    String expectedCapabilityDigest = ContractJson.sha256(capability);
                    return host.gameTask(() -> {
                        pairingControl.run();
                        byte[] privateCapability = capability.clone();
                        if (!expectedCapabilityDigest.equals(ContractJson.sha256(privateCapability))) {
                            Arrays.fill(privateCapability, (byte) 0); throw new ContractException("HOST_PAIRING_CANCELLED", "Pairing capability lifetime ended before installation");
                        }
                        try {
                        var compatibilityApprovals = validateAuthority(offer, setup, authority);
                        pairingControl.run();
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
                        try { endpoint = host.install(playerId, offer.path("principalId").asText(), bearer, permissions, contexts, sources, actions, false, compatibilityApprovals, pairingControl); }
                        catch (java.io.IOException exception) { throw new ContractException("HOST_PAIRING_FAILED", "The paired loopback listener could not be started"); }
                        finally { Arrays.fill(bearer, (byte) 0); }
                        try { pairingControl.run(); }
                        catch (RuntimeException failure) { host.revokePairing(epoch); throw failure; }
                        ObjectNode installed = ContractJson.newObject().put("kind", "host_pairing_installed").put("protocolVersion", ContractJson.VERSION)
                                .put("nonce", offer.path("nonce").asText());
                        var uri = java.net.URI.create(endpoint);
                        installed.putObject("hostEndpoint").put("address", "127.0.0.1:" + uri.getPort()).put("path", "/rpc").put("hostEpoch", epoch);
                        pairingControl.run();
                        return installed;
                        } finally { Arrays.fill(privateCapability, (byte) 0); }
                    }); });
            pairingControl.run();
            HostDispatcher.exactFields(completed, Set.of("kind", "protocolVersion", "nonce", "ready", "coordinatorEpoch", "hostEpoch", "contextId"));
            if (!completed.path("hostEpoch").asText().equals(installedEpoch.get())) throw new ContractException("SESSION_EPOCH_MISMATCH", "Pairing completion belongs to another host generation");
            if (!installedContexts.get().contains(completed.path("contextId").asText()) || !completed.path("coordinatorEpoch").isTextual()
                    || !completed.path("coordinatorEpoch").asText().matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw invalid();
            pairingControl.run();
        } catch (RuntimeException exception) {
            cancelled.set(true); host.revokePairing(installedEpoch.get()); throw exception;
        } finally { Arrays.fill(raw, (byte) 0); }
    }
    private List<NativeCompatibilityApprovals.ApprovedProfile> validateAuthority(ObjectNode offer, HostSetup setup, ObjectNode authority) {
        HostDispatcher.exactFields(authority, Set.of("kind", "protocolVersion", "nonce", "contexts", "approvedSources", "approvedActions", "permissions", "writeProfileVerified", "compatibilityApprovals"));
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
        return decodeCompatibilityApprovals(authority.get("compatibilityApprovals"));
    }

    /** Private owner bridge transport only; decoding these values does not issue or install an approval. */
    static List<NativeCompatibilityApprovals.ApprovedProfile> decodeCompatibilityApprovals(JsonNode value) {
        ObjectNode collection = ContractJson.object(value);
        HostDispatcher.exactFields(collection, Set.of("status", "reasonCode", "profiles"));
        JsonNode status = collection.get("status"); JsonNode reason = collection.get("reasonCode"); JsonNode profiles = collection.get("profiles");
        if (!status.isTextual() || !profiles.isArray() || profiles.size() > 128) throw invalid();
        if ("unavailable".equals(status.asText())) {
            if (!reason.isTextual() || !"APPROVAL_SOURCE_UNAVAILABLE".equals(reason.asText()) || !profiles.isEmpty()) throw invalid();
            return List.of();
        }
        if (!"available".equals(status.asText()) || !reason.isNull()) throw invalid();
        var decoded = new ArrayList<NativeCompatibilityApprovals.ApprovedProfile>(); var references = new HashSet<String>();
        int rawBytes = 0;
        for (JsonNode element : profiles) {
            ObjectNode profile = ContractJson.object(element);
            HostDispatcher.exactFields(profile, Set.of("approvedProfileRef", "profileBytesHex", "profileDigest", "artifactDigest", "allowedInterfaceDigest"));
            String reference = HostDispatcher.string(profile, "approvedProfileRef"); String hex = HostDispatcher.string(profile, "profileBytesHex");
            String profileDigest = HostDispatcher.string(profile, "profileDigest"); String artifactDigest = HostDispatcher.string(profile, "artifactDigest");
            String interfaceDigest = HostDispatcher.string(profile, "allowedInterfaceDigest");
            if (!reference.matches("[A-Za-z0-9_.:-]{1,256}") || !references.add(reference)
                    || hex.length() < 2 || hex.length() > 2 * 65536 || (hex.length() & 1) != 0 || !hex.matches("[a-f0-9]+")
                    || !profileDigest.matches("[a-f0-9]{64}") || !artifactDigest.matches("[a-f0-9]{64}") || !interfaceDigest.matches("[a-f0-9]{64}")) throw invalid();
            rawBytes += hex.length() / 2; if (rawBytes > 256 * 1024) throw invalid();
            decoded.add(new NativeCompatibilityApprovals.ApprovedProfile(reference, HexFormat.of().parseHex(hex), profileDigest, artifactDigest, interfaceDigest));
        }
        return List.copyOf(decoded);
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
