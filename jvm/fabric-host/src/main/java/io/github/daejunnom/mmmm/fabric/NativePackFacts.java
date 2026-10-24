package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.fabric.mixin.FixedPathPackReadAccess;
import io.github.daejunnom.mmmm.fabric.mixin.ModNioPackReadAccess;
import io.github.daejunnom.mmmm.fabric.mixin.OverlayedPackReadAccess;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import net.fabricmc.fabric.impl.resource.pack.ModNioPackResources;
import net.minecraft.server.packs.FixedPathPackResources;
import net.minecraft.server.packs.OverlayedPackResources;
import net.minecraft.server.packs.PackResources;
import net.minecraft.server.packs.PackType;

/** 현재 실제 pack 구조만 관측한다. resource 조회·overlay 생성·filter 승인·권한 발급은 하지 않는다. */
final class NativePackFacts {
    @FunctionalInterface interface RootResolver { RootLink resolve(Path root); }
    record RootLink(String sourceId, String memberPrefix, String reason) {
        static RootLink unknown(String reason) { return new RootLink(null, null, reason); }
    }
    record Observation(ObjectNode facts, int entries, Runnable revalidate) { }
    private record Snapshot(PackResources actual, String kind, List<Path> roots,
                            Map<PackType, List<Path>> typedRoots, PackType type,
                            PackResources primary, List<PackResources> stack) { }
    private static final List<PackType> TYPE_ORDER = List.of(PackType.CLIENT_RESOURCES, PackType.SERVER_DATA);
    private static final int MAX_ENTRIES = 256;
    private final NativeSourceFacts.Checkpoint checkpoint;
    private final RootResolver resolver;
    private final int allowance;
    private final IdentityHashMap<PackResources, Integer> indexes = new IdentityHashMap<>();
    private final IdentityHashMap<PackResources, Boolean> active = new IdentityHashMap<>();
    private final List<Snapshot> snapshots = new ArrayList<>();
    private final ArrayNode nodes = ContractJson.newObject().putArray("nodes");
    private int used;

    private NativePackFacts(NativeSourceFacts.Checkpoint checkpoint, RootResolver resolver, int allowance) {
        this.checkpoint = Objects.requireNonNull(checkpoint); this.resolver = Objects.requireNonNull(resolver);
        if (allowance < 0 || allowance > MAX_ENTRIES) throw new IllegalArgumentException("Pack fact allowance");
        this.allowance = allowance;
    }

    static Observation observe(PackResources actual, NativeSourceFacts.Checkpoint checkpoint,
                               RootResolver resolver, int allowance, int byteAllowance) {
        NativePackFacts collector = new NativePackFacts(checkpoint, resolver, allowance);
        collector.checkpoint.check();
        try {
            collector.visit(Objects.requireNonNull(actual));
            collector.revalidate();
            ObjectNode facts = envelope().put("status", "observed").putNull("reason").put("rootNode", 0);
            facts.set("nodes", collector.nodes);
            collector.checkpoint.check(); byte[] encoded = ContractJson.bytes(facts); collector.checkpoint.check();
            if (encoded.length > byteAllowance) throw new Unavailable("PACK_FACTS_LIMIT");
            return new Observation(facts, collector.used, collector::revalidate);
        } catch (Unavailable failure) {
            collector.checkpoint.check();
            return new Observation(unknown(failure.reason), collector.used, collector::revalidate);
        } catch (LinkageError | AssertionError failure) {
            collector.checkpoint.check();
            return new Observation(unknown("NATIVE_PACK_ACCESS_UNAVAILABLE"), collector.used, collector::revalidate);
        }
    }

    static ObjectNode unknown(String reason) {
        ObjectNode result = envelope().put("status", "unknown").put("reason", reason).putNull("rootNode");
        result.putArray("nodes"); return result;
    }

    private static ObjectNode envelope() {
        ObjectNode result = ContractJson.newObject().put("format", "mmmm.native.pack-facts/1");
        result.putObject("filter").put("status", "unknown").put("reason", "NATIVE_FILTER_MAPPING_UNOBSERVED");
        return result;
    }

    private void charge() {
        checkpoint.check();
        if (used >= allowance) throw new Unavailable("PACK_FACTS_LIMIT");
        used++;
    }

    private int visit(PackResources actual) {
        checkpoint.check();
        if (active.containsKey(actual)) throw new Unavailable("PACK_GRAPH_CYCLE");
        Integer existing = indexes.get(actual);
        if (existing != null) return existing;
        charge();
        int index = indexes.size();
        Snapshot snapshot = read(actual, true);
        indexes.put(actual, index); snapshots.add(snapshot); active.put(actual, Boolean.TRUE);
        ObjectNode node = nodes.addObject().put("nodeIndex", index).put("kind", snapshot.kind());
        switch (snapshot.kind()) {
            case "fixed_path" -> {
                node.set("packRoots", roots(snapshot.roots(), "pack_root"));
                ArrayNode typed = node.putArray("typeRoots");
                for (PackType type : TYPE_ORDER) {
                    checkpoint.check();
                    List<Path> paths = snapshot.typedRoots().get(type);
                    if (paths != null) {
                        ObjectNode item = typed.addObject().put("packType", typeName(type));
                        item.set("roots", roots(paths, "type_root"));
                    }
                }
            }
            case "mod_nio" -> {
                node.put("packType", typeName(snapshot.type()));
                node.set("roots", roots(snapshot.roots(), "pack_root"));
            }
            case "overlayed" -> {
                node.put("primaryNode", visit(snapshot.primary()));
                ArrayNode stack = node.putArray("resourceStack");
                for (PackResources child : snapshot.stack()) { checkpoint.check(); stack.add(visit(child)); }
            }
            default -> throw new Unavailable("PACK_IMPLEMENTATION_UNSUPPORTED");
        }
        active.remove(actual); checkpoint.check(); return index;
    }

    private ArrayNode roots(List<Path> paths, String scope) {
        ArrayNode result = ContractJson.newObject().putArray("roots");
        for (Path path : paths) {
            checkpoint.check(); RootLink link = resolver.resolve(path); checkpoint.check();
            ObjectNode root = result.addObject().put("scope", scope);
            if (link.reason() == null) {
                root.put("status", "observed").putNull("reason").put("sourceId", link.sourceId()).put("memberPrefix", link.memberPrefix());
            } else {
                root.put("status", "unknown").put("reason", link.reason()).putNull("sourceId").putNull("memberPrefix");
            }
        }
        return result;
    }

    private Snapshot read(PackResources actual, boolean count) {
        checkpoint.check();
        Class<?> type = actual.getClass();
        Snapshot result;
        if (type == FixedPathPackResources.class) {
            if (!(actual instanceof FixedPathPackReadAccess access)) throw new Unavailable("NATIVE_PACK_ACCESS_UNAVAILABLE");
            List<Path> roots = paths(access.mmmm$rootPaths(), count);
            checkpoint.check(); Map<PackType, List<Path>> raw = access.mmmm$pathsForType(); checkpoint.check();
            if (raw == null || raw.size() > TYPE_ORDER.size()) throw new Unavailable("PACK_FACTS_UNAVAILABLE");
            for (PackType key : raw.keySet()) {
                checkpoint.check(); if (!TYPE_ORDER.contains(key)) throw new Unavailable("PACK_TYPE_UNSUPPORTED");
            }
            Map<PackType, List<Path>> typed = new EnumMap<>(PackType.class);
            for (PackType key : TYPE_ORDER) {
                checkpoint.check(); if (raw.containsKey(key)) typed.put(key, paths(raw.get(key), count));
            }
            result = new Snapshot(actual, "fixed_path", roots, typed, null, null, List.of());
        } else if (type == ModNioPackResources.class) {
            if (!(actual instanceof ModNioPackReadAccess access)) throw new Unavailable("NATIVE_PACK_ACCESS_UNAVAILABLE");
            List<Path> roots = paths(access.mmmm$basePaths(), count);
            checkpoint.check(); PackType packType = access.mmmm$type(); checkpoint.check(); typeName(packType);
            result = new Snapshot(actual, "mod_nio", roots, Map.of(), packType, null, List.of());
        } else if (type == OverlayedPackResources.class) {
            if (!(actual instanceof OverlayedPackReadAccess access)) throw new Unavailable("NATIVE_PACK_ACCESS_UNAVAILABLE");
            checkpoint.check(); Object primary = access.mmmm$primaryPackMetadataResources(); checkpoint.check();
            if (!(primary instanceof PackResources pack)) throw new Unavailable("PACK_FACTS_UNAVAILABLE");
            if (count) charge();
            checkpoint.check(); List<PackResources> raw = access.mmmm$packResourcesStack(); checkpoint.check();
            if (raw == null) throw new Unavailable("PACK_FACTS_UNAVAILABLE");
            List<PackResources> stack = new ArrayList<>();
            for (PackResources child : raw) {
                checkpoint.check(); if (count) charge();
                if (child == null || stack.size() >= MAX_ENTRIES) throw new Unavailable("PACK_FACTS_UNAVAILABLE");
                stack.add(child);
            }
            result = new Snapshot(actual, "overlayed", List.of(), Map.of(), null, pack, List.copyOf(stack));
        } else throw new Unavailable("PACK_IMPLEMENTATION_UNSUPPORTED");
        checkpoint.check(); return result;
    }

    private List<Path> paths(List<Path> raw, boolean count) {
        checkpoint.check();
        if (raw == null) throw new Unavailable("PACK_FACTS_UNAVAILABLE");
        List<Path> result = new ArrayList<>();
        for (Path path : raw) {
            checkpoint.check(); if (count) charge();
            if (path == null || result.size() >= MAX_ENTRIES) throw new Unavailable("PACK_FACTS_UNAVAILABLE");
            result.add(path);
        }
        checkpoint.check(); return List.copyOf(result);
    }

    private void revalidate() {
        checkpoint.check();
        for (Snapshot snapshot : snapshots) {
            Snapshot current;
            try { current = read(snapshot.actual(), false); }
            catch (Unavailable | LinkageError | AssertionError failure) {
                checkpoint.check(); throw drift(failure);
            }
            if (!snapshot.roots().equals(current.roots()) || !snapshot.typedRoots().equals(current.typedRoots())
                    || snapshot.type() != current.type() || snapshot.primary() != current.primary()
                    || snapshot.stack().size() != current.stack().size()) throw drift(null);
            for (int i = 0; i < snapshot.stack().size(); i++) {
                checkpoint.check(); if (snapshot.stack().get(i) != current.stack().get(i)) throw drift(null);
            }
            checkpoint.check();
        }
    }

    private static ContractException drift(Throwable cause) {
        ContractException failure = new ContractException("SOURCE_FACTS_DRIFT", "현재 pack 구조가 관측 중 바뀌었습니다");
        if (cause != null) failure.initCause(cause);
        return failure;
    }

    private static String typeName(PackType type) {
        if (type == PackType.CLIENT_RESOURCES) return "client_resources";
        if (type == PackType.SERVER_DATA) return "server_data";
        throw new Unavailable("PACK_TYPE_UNSUPPORTED");
    }

    private static final class Unavailable extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String reason;
        private Unavailable(String reason) { super(reason); this.reason = reason; }
    }
}
