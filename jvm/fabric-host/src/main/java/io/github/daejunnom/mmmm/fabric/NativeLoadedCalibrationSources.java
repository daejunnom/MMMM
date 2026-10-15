package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.sdk.ContractException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.functions.CommandFunction;
import net.minecraft.core.registries.Registries;
import net.minecraft.resources.FileToIdConverter;
import net.minecraft.resources.Identifier;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.ServerFunctionLibrary;

/**
 * 현재 선택된 함수 source와 실제 등록 함수 object의 읽기 전용 관측이다.
 * 정본 recipe의 출처, 실제 load와 source 사이의 인과 증명, 실행 허가 또는 profile이 아니다.
 * 설치·reload·parse·instantiate·handler 실행과 JSON 발급은 이 경계에 없다.
 */
final class NativeLoadedCalibrationSources {
    static final int MAX_FUNCTIONS = 47;
    static final int MAX_SOURCE_BYTES = 64 * 1024;
    static final int MAX_TOTAL_SOURCE_BYTES = 1024 * 1024;
    static final int MAX_PACKS = 256;
    private static final int CHUNK_BYTES = 8192;
    // 각 pass는 exact 기대 길이 뒤 EOF 확인에 최대 1 byte만 더 읽는다.
    private static final long MAX_READ_BYTES = 2L * (MAX_TOTAL_SOURCE_BYTES + MAX_FUNCTIONS);

    private NativeLoadedCalibrationSources() { }

    @FunctionalInterface interface Checkpoint { void check(); }

    /** 비교 입력이다. 이 타입을 만들거나 hash를 아는 행위는 Rust 정본 또는 권한을 증명하지 않는다. */
    record ExpectedSource<K>(K functionId, K resourceId, byte[] bytes) {
        ExpectedSource {
            Objects.requireNonNull(functionId); Objects.requireNonNull(resourceId); Objects.requireNonNull(bytes);
            if (bytes.length > MAX_SOURCE_BYTES) throw failure("CALIBRATION_SOURCE_LIMIT");
            bytes = bytes.clone();
        }
        @Override public byte[] bytes() { return bytes.clone(); }
    }

    /** 실제 server adapter만 이 production view를 생성한다. test port의 RawFacts는 변환할 수 없다. */
    static final class ObservedSources {
        private final List<LoadedFunction> functions;
        private final long sourceBytes;
        private final long readBytes;

        private ObservedSources(RawFacts<Identifier, CommandFunction<CommandSourceStack>> facts) {
            var observed = new ArrayList<LoadedFunction>(facts.sources.size());
            for (var source : facts.sources) observed.add(new LoadedFunction(source));
            functions = List.copyOf(observed); sourceBytes = facts.sourceBytes; readBytes = facts.readBytes;
        }
        List<LoadedFunction> functions() { return functions; }
        long sourceBytes() { return sourceBytes; }
        long readBytes() { return readBytes; }
    }

    /** 원래 object를 보존하지만 호출 권한은 없다. 후속 runner는 새 원 요청으로 현재성을 재검사해야 한다. */
    static final class LoadedFunction {
        private final RawSource<Identifier, CommandFunction<CommandSourceStack>> source;
        private LoadedFunction(RawSource<Identifier, CommandFunction<CommandSourceStack>> source) { this.source = source; }
        Identifier functionId() { return source.expected.functionId; }
        Identifier resourceId() { return source.expected.resourceId; }
        String sourcePackId() { return source.sourcePackId; }
        String sha256() { return source.sha256; }
        byte[] bytes() { return source.bytes.clone(); }
        CommandFunction<CommandSourceStack> function() { return source.function; }
    }

    /**
     * 원 callback은 host의 paired/context/server/epoch/registry generation, reload와 원 deadline/cancel을 검사해야 한다.
     * live host 연결은 별도 단계이며, 여기의 server-thread 검사는 native owner/ADMIN 승인을 대신하지 않는다.
     * 외부 writer에 대한 원자적 파일 snapshot도 주장하지 않는다. 후속 실행 직전의 새 현재성 검사가 필요하다.
     */
    static ObservedSources observe(MinecraftServer server, List<ExpectedSource<Identifier>> expected,
                                   Checkpoint original) {
        Objects.requireNonNull(server); Objects.requireNonNull(original);
        Checkpoint checkpoint = () -> {
            original.check();
            if (!server.isSameThread()) throw failure("CALIBRATION_SOURCE_THREAD_REQUIRED");
        };
        checkpoint.check();
        var facts = scan(new ActualPort(server), expected, checkpoint);
        checkpoint.check();
        var observed = new ObservedSources(facts);
        checkpoint.check();
        return observed;
    }

    /** 순수 scanner 입력은 테스트 가능하지만 actual production view의 발급 port가 아니다. */
    interface ReadPort<K, F> {
        void validateMapping(ExpectedSource<K> source);
        View view(Checkpoint checkpoint);
        Source<F> resolve(ExpectedSource<K> expected, Checkpoint checkpoint);
    }

    record View(Object resources, Object functions, Object repository, List<?> selectedPacks,
                List<String> selectedIds, List<?> resourcePacks) {
        View {
            Objects.requireNonNull(resources); Objects.requireNonNull(functions); Objects.requireNonNull(repository);
            selectedPacks = List.copyOf(selectedPacks); selectedIds = List.copyOf(selectedIds);
            resourcePacks = List.copyOf(resourcePacks);
        }
    }

    @FunctionalInterface interface OpenSource { InputStream open() throws IOException; }
    record Source<F>(F function, Object sourcePack, String sourcePackId, OpenSource open) {
        Source { Objects.requireNonNull(function); Objects.requireNonNull(sourcePack); Objects.requireNonNull(sourcePackId); Objects.requireNonNull(open); }
    }

    /** 합성 fixture 자료도 포함하는 일반 관측값이다. 승인·JSON·production view 변환 API는 없다. */
    static final class RawFacts<K, F> {
        private final List<RawSource<K, F>> sources;
        private final long sourceBytes;
        private final long readBytes;
        private RawFacts(List<RawSource<K, F>> sources, long sourceBytes, long readBytes) {
            this.sources = List.copyOf(sources); this.sourceBytes = sourceBytes; this.readBytes = readBytes;
        }
        int size() { return sources.size(); }
        long sourceBytes() { return sourceBytes; }
        long readBytes() { return readBytes; }
        byte[] bytes(int index) { return sources.get(index).bytes.clone(); }
        String sha256(int index) { return sources.get(index).sha256; }
        F function(int index) { return sources.get(index).function; }
    }

    private record RawSource<K, F>(ExpectedSource<K> expected, F function, Object sourcePack,
                                   String sourcePackId, byte[] bytes, String sha256) { }
    private static final class ReadBudget { private long bytes; }

    static <K, F> RawFacts<K, F> scan(ReadPort<K, F> port, List<ExpectedSource<K>> inputs, Checkpoint checkpoint) {
        Objects.requireNonNull(port); Objects.requireNonNull(inputs); Objects.requireNonNull(checkpoint);
        checkpoint.check();
        if (inputs.isEmpty() || inputs.size() > MAX_FUNCTIONS) throw failure("CALIBRATION_SOURCE_LIMIT");
        List<ExpectedSource<K>> expected = List.copyOf(inputs);
        Set<K> functions = new HashSet<>(), resources = new HashSet<>();
        long total = 0;
        for (var input : expected) {
            checkpoint.check(); port.validateMapping(input); checkpoint.check();
            if (!functions.add(input.functionId) || !resources.add(input.resourceId)) throw failure("CALIBRATION_SOURCE_DUPLICATE");
            total += input.bytes.length;
            if (total > MAX_TOTAL_SOURCE_BYTES) throw failure("CALIBRATION_SOURCE_LIMIT");
        }
        View initial = checked(() -> port.view(checkpoint), checkpoint); validateView(initial, checkpoint);
        var observed = new ArrayList<RawSource<K, F>>(expected.size());
        var budget = new ReadBudget();
        for (var input : expected) {
            checkpoint.check();
            Source<F> source = checked(() -> port.resolve(input, checkpoint), checkpoint);
            validateSource(initial, source, checkpoint);
            String digest = read(source, input.bytes, budget, checkpoint);
            // 유지하는 원문은 비교를 통과한 첫 pass의 exact bytes이다. 두 번째 read buffer는 누적하지 않는다.
            observed.add(new RawSource<>(input, source.function, source.sourcePack, source.sourcePackId, input.bytes, digest));
        }
        assertView(initial, checked(() -> port.view(checkpoint), checkpoint), checkpoint);
        for (var source : observed) {
            checkpoint.check();
            Source<F> current = checked(() -> port.resolve(source.expected, checkpoint), checkpoint);
            assertSource(source, current); validateSource(initial, current, checkpoint);
            if (!source.sha256.equals(read(current, source.bytes, budget, checkpoint))) throw failure("CALIBRATION_SOURCE_CHANGED");
        }
        // 첫 함수의 post-read 이후 다른 함수를 읽는 동안 원 function/source object가 바뀌어도 완료하지 않는다.
        for (var source : observed) {
            checkpoint.check();
            assertSource(source, checked(() -> port.resolve(source.expected, checkpoint), checkpoint));
        }
        assertView(initial, checked(() -> port.view(checkpoint), checkpoint), checkpoint); checkpoint.check();
        return new RawFacts<>(observed, total, budget.bytes);
    }

    private static <T> T checked(Supplier<T> action, Checkpoint checkpoint) {
        checkpoint.check(); Throwable original = null;
        try { return action.get(); }
        catch (RuntimeException | Error error) { original = error; throw error; }
        finally {
            try { checkpoint.check(); }
            catch (RuntimeException | Error current) {
                if (original != null && current != original) current.addSuppressed(original);
                throw current;
            }
        }
    }

    private static void validateView(View view, Checkpoint checkpoint) {
        if (view.selectedPacks.size() > MAX_PACKS || view.selectedIds.size() > MAX_PACKS || view.resourcePacks.size() > MAX_PACKS)
            throw failure("CALIBRATION_SOURCE_LIMIT");
        for (String id : view.selectedIds) { checkpoint.check(); validatePackId(id); }
    }

    private static void validatePackId(String id) {
        if (id.isEmpty() || id.length() > 1024 || id.indexOf('\0') >= 0) throw failure("CALIBRATION_SOURCE_UNAVAILABLE");
    }

    private static void validateSource(View view, Source<?> source, Checkpoint checkpoint) {
        validatePackId(source.sourcePackId);
        boolean actualPack = false;
        for (Object pack : view.resourcePacks) {
            checkpoint.check(); if (pack == source.sourcePack) { actualPack = true; break; }
        }
        if (!actualPack) throw failure("CALIBRATION_SOURCE_CHANGED");
    }

    private static void assertView(View expected, View current, Checkpoint checkpoint) {
        validateView(current, checkpoint);
        if (expected.resources != current.resources || expected.functions != current.functions || expected.repository != current.repository
                || !sameObjects(expected.selectedPacks, current.selectedPacks, checkpoint) || !expected.selectedIds.equals(current.selectedIds)
                || !sameObjects(expected.resourcePacks, current.resourcePacks, checkpoint)) throw failure("CALIBRATION_SOURCE_CHANGED");
    }

    private static boolean sameObjects(List<?> left, List<?> right, Checkpoint checkpoint) {
        if (left.size() != right.size()) return false;
        for (int index = 0; index < left.size(); index++) {
            checkpoint.check(); if (left.get(index) != right.get(index)) return false;
        }
        return true;
    }

    private static void assertSource(RawSource<?, ?> expected, Source<?> current) {
        if (expected.function != current.function || expected.sourcePack != current.sourcePack
                || !expected.sourcePackId.equals(current.sourcePackId)) throw failure("CALIBRATION_SOURCE_CHANGED");
    }

    private static String read(Source<?> source, byte[] expected, ReadBudget budget, Checkpoint checkpoint) {
        InputStream stream = null;
        Throwable original = null;
        try {
            checkpoint.check(); stream = Objects.requireNonNull(source.open.open()); checkpoint.check();
            MessageDigest digest = sha256(); byte[] chunk = new byte[CHUNK_BYTES]; int offset = 0;
            while (true) {
                checkpoint.check();
                int maximum = Math.min(chunk.length, expected.length - offset + 1);
                int count = stream.read(chunk, 0, maximum);
                checkpoint.check();
                if (count == -1) break;
                if (count <= 0 || count > maximum) throw failure("CALIBRATION_SOURCE_READ_STALLED");
                budget.bytes += count;
                if (budget.bytes > MAX_READ_BYTES) throw failure("CALIBRATION_SOURCE_LIMIT");
                if (count > expected.length - offset) throw failure("CALIBRATION_SOURCE_MISMATCH");
                for (int index = 0; index < count; index++) {
                    if ((index & 1023) == 0) checkpoint.check();
                    if (chunk[index] != expected[offset + index]) throw failure("CALIBRATION_SOURCE_MISMATCH");
                }
                digest.update(chunk, 0, count); offset += count;
            }
            if (offset != expected.length) throw failure("CALIBRATION_SOURCE_MISMATCH");
            checkpoint.check();
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException error) {
            RuntimeException wrapped = ioFailure(error); original = wrapped; throw wrapped;
        } catch (RuntimeException | Error error) {
            original = error; throw error;
        } finally {
            // 취소되어도 우리가 연 stream은 닫는다. 원문 예외/현재성 실패를 unknown 또는 성공으로 바꾸지 않는다.
            Throwable terminal = null;
            try { checkpoint.check(); } catch (RuntimeException | Error error) { terminal = error; }
            if (stream != null) {
                try { stream.close(); } catch (IOException error) {
                    if (terminal == null) terminal = ioFailure(error); else terminal.addSuppressed(error);
                } catch (RuntimeException | Error error) {
                    if (terminal == null) terminal = error; else if (terminal != error) terminal.addSuppressed(error);
                }
            }
            try { checkpoint.check(); } catch (RuntimeException | Error error) {
                if (terminal != null && terminal != error) error.addSuppressed(terminal);
                terminal = error;
            }
            if (terminal != null) {
                if (original != null && terminal != original) terminal.addSuppressed(original);
                if (terminal instanceof RuntimeException runtime) throw runtime;
                throw (Error) terminal;
            }
        }
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException error) { throw new IllegalStateException("SHA-256 unavailable", error); }
    }

    private static ContractException ioFailure(IOException cause) {
        ContractException failure = failure("CALIBRATION_SOURCE_READ_FAILED"); failure.initCause(cause); return failure;
    }

    private static ContractException failure(String code) {
        return new ContractException(code, "현재 calibration 함수 source 관측을 완료하지 못했습니다");
    }

    private static final class ActualPort implements ReadPort<Identifier, CommandFunction<CommandSourceStack>> {
        private final MinecraftServer server;
        private View initial;
        private final FileToIdConverter converter = new FileToIdConverter(
                Registries.elementsDirPath(ServerFunctionLibrary.TYPE_KEY), ".mcfunction");

        private ActualPort(MinecraftServer server) { this.server = server; }

        @Override public void validateMapping(ExpectedSource<Identifier> source) {
            String function = source.functionId.toString(), resource = source.resourceId.toString();
            if (function.length() > 1024 || resource.length() > 1024 || !function.startsWith("mmmm_calibration:")
                    || !converter.matches(source.resourceId) || !converter.idToFile(source.functionId).equals(source.resourceId)
                    || !converter.fileToId(source.resourceId).equals(source.functionId)) throw failure("CALIBRATION_SOURCE_MAPPING_MISMATCH");
        }

        @Override public View view(Checkpoint checkpoint) {
            checkpoint.check();
            var resources = server.getResourceManager(); var functions = server.getFunctions(); var repository = server.getPackRepository();
            var selected = bounded(repository.getSelectedPacks().iterator(), checkpoint);
            var ids = bounded(repository.getSelectedIds().iterator(), checkpoint);
            List<?> packs;
            try (var stream = resources.listPacks()) { packs = bounded(stream.iterator(), checkpoint); }
            checkpoint.check();
            if (server.getResourceManager() != resources || server.getFunctions() != functions || server.getPackRepository() != repository)
                throw failure("CALIBRATION_SOURCE_CHANGED");
            View view = new View(resources, functions, repository, selected, ids, packs);
            if (initial == null) initial = view;
            return view;
        }

        @Override public Source<CommandFunction<CommandSourceStack>> resolve(ExpectedSource<Identifier> expected, Checkpoint checkpoint) {
            checkpoint.check();
            var resources = server.getResourceManager(); var functions = server.getFunctions();
            if (initial == null || resources != initial.resources || functions != initial.functions
                    || server.getPackRepository() != initial.repository) throw failure("CALIBRATION_SOURCE_CHANGED");
            var function = functions.get(expected.functionId).orElseThrow(() -> failure("CALIBRATION_FUNCTION_UNAVAILABLE"));
            var resource = resources.getResource(expected.resourceId).orElseThrow(() -> failure("CALIBRATION_SOURCE_UNAVAILABLE"));
            checkpoint.check();
            if (server.getResourceManager() != resources || server.getFunctions() != functions
                    || functions.get(expected.functionId).orElse(null) != function || !function.id().equals(expected.functionId))
                throw failure("CALIBRATION_SOURCE_CHANGED");
            return new Source<>(function, resource.source(), resource.sourcePackId(), resource::open);
        }

        private static <T> List<T> bounded(Iterator<T> iterator, Checkpoint checkpoint) {
            var values = new ArrayList<T>();
            while (true) {
                checkpoint.check(); if (!iterator.hasNext()) break; checkpoint.check();
                if (values.size() == MAX_PACKS) throw failure("CALIBRATION_SOURCE_LIMIT");
                values.add(Objects.requireNonNull(iterator.next())); checkpoint.check();
            }
            return List.copyOf(values);
        }
    }
}
