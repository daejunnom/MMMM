package io.github.daejunnom.mmmm.fabric;

import io.github.daejunnom.mmmm.sdk.ContractException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.IntConsumer;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 기존 fixture에는 manager·함수·winner source identity와 두 번의 stream read 경계가 없다.
 * 이 순수 port fixture는 RawFacts만 검사하며 실제 게임 관측이나 production view를 만들지 않는다.
 */
final class NativeLoadedCalibrationSourcesTest {
    private static final NativeLoadedCalibrationSources.Checkpoint OPEN = () -> { };

    @Test void exactTwoPassFactsPreserveOriginalObjectsAndDefensiveBytesWithoutAnApproval() {
        Fixture fixture = new Fixture(); var expected = fixture.add("one", "scoreboard players set #ok test 0\n");
        byte[] copied = expected.bytes(); copied[0] = 0;
        var facts = fixture.scan(List.of(expected), OPEN);
        assertEquals(1, facts.size()); assertEquals(expected.bytes().length, facts.sourceBytes());
        assertEquals(2L * expected.bytes().length, facts.readBytes());
        assertEquals(64, facts.sha256(0).length()); assertSame(fixture.states.get("one").function, facts.function(0));
        assertArrayEquals(expected.bytes(), facts.bytes(0)); byte[] output = facts.bytes(0); output[0] = 0;
        assertArrayEquals(expected.bytes(), facts.bytes(0)); assertEquals(2, fixture.opens); assertEquals(2, fixture.closes);
        assertEquals(3, fixture.resolves);
    }

    @Test void originalCancellationBeforeAccessAndAfterReadKeepsItsThrowableAndClosesOnlyOpenedStreams() {
        Fixture fixture = new Fixture(); var input = fixture.add("one", "data get storage fixture:data value\n");
        ContractException cancelled = new ContractException("CANCELLATION_REQUESTED", "원 요청이 취소되었습니다");
        assertSame(cancelled, assertThrows(ContractException.class, () -> fixture.scan(List.of(input), () -> { throw cancelled; })));
        assertEquals(0, fixture.views); assertEquals(0, fixture.resolves); assertEquals(0, fixture.opens);
        AtomicBoolean stopped = new AtomicBoolean(); fixture.afterRead = ignored -> stopped.set(true);
        assertSame(cancelled, assertThrows(ContractException.class,
                () -> fixture.scan(List.of(input), () -> { if (stopped.get()) throw cancelled; })));
        assertEquals(1, fixture.opens); assertEquals(1, fixture.closes); assertEquals(1, fixture.resolves);
    }

    @Test void currentnessFailureAfterCloseRetainsTheOriginalIoFailureInsteadOfReturningUnknown() {
        Fixture fixture = new Fixture(); var input = fixture.add("one", "scoreboard players reset #ok test\n");
        IOException io = new IOException("fixture read failure"); fixture.readFailure = io;
        ContractException stale = new ContractException("CONTEXT_STALE", "원 환경이 바뀌었습니다");
        AtomicBoolean changed = new AtomicBoolean(); fixture.afterClose = ignored -> changed.set(true);
        ContractException result = assertThrows(ContractException.class,
                () -> fixture.scan(List.of(input), () -> { if (changed.get()) throw stale; }));
        assertSame(stale, result); assertEquals(1, fixture.closes);
        assertEquals(1, result.getSuppressed().length); assertSame(io, result.getSuppressed()[0].getCause());
    }

    @Test void exactBytesAndBoundedEofRejectChangedShortLongAndStalledSources() {
        for (String actual : List.of("different\n", "", "source\nextra")) {
            Fixture fixture = new Fixture(); var input = fixture.add("one", "source\n");
            fixture.states.get("one").bytes = actual.getBytes(StandardCharsets.UTF_8);
            assertCode("CALIBRATION_SOURCE_MISMATCH", () -> fixture.scan(List.of(input), OPEN));
            assertEquals(1, fixture.opens); assertEquals(1, fixture.closes);
            assertTrue(fixture.delivered <= input.bytes().length + 1);
        }
        Fixture fixture = new Fixture(); var input = fixture.add("one", "source\n"); fixture.stalled = true;
        assertCode("CALIBRATION_SOURCE_READ_STALLED", () -> fixture.scan(List.of(input), OPEN)); assertEquals(1, fixture.closes);
    }

    @Test void selectionManagerAndWinnerIdentityChangesNeverCompleteEvenWhenLabelsAndBytesMatch() {
        for (String change : List.of("selection", "manager", "function", "winner")) {
            Fixture fixture = new Fixture(); var input = fixture.add("one", "source\n");
            fixture.afterClose = count -> {
                if (count != 1) return;
                switch (change) {
                    case "selection" -> fixture.selectedPacks = List.of(new Object());
                    case "manager" -> fixture.resources = new Object();
                    case "function" -> fixture.states.get("one").function = new Object();
                    case "winner" -> fixture.states.get("one").pack = new Object();
                    default -> throw new AssertionError();
                }
            };
            assertCode("CALIBRATION_SOURCE_CHANGED", () -> fixture.scan(List.of(input), OPEN));
            assertTrue(fixture.opens <= 1); assertEquals(fixture.opens, fixture.closes);
        }
    }

    @Test void finalFunctionIdentityAndSecondPassBytesAreCheckedAfterTheFirstRead() {
        Fixture changed = new Fixture(); var first = changed.add("one", "first\n"); var second = changed.add("two", "second\n");
        changed.afterClose = count -> { if (count == 4) changed.states.get("one").function = new Object(); };
        assertCode("CALIBRATION_SOURCE_CHANGED", () -> changed.scan(List.of(first, second), OPEN));
        assertEquals(4, changed.opens); assertEquals(4, changed.closes);
        Fixture bytes = new Fixture(); var input = bytes.add("one", "source\n");
        bytes.afterClose = count -> { if (count == 1) bytes.states.get("one").bytes = "change\n".getBytes(StandardCharsets.UTF_8); };
        assertCode("CALIBRATION_SOURCE_MISMATCH", () -> bytes.scan(List.of(input), OPEN));
        assertEquals(2, bytes.opens); assertEquals(2, bytes.closes);
    }

    @Test void inputLimitsDuplicatesAndMappingAreRejectedBeforeOpeningAnySource() {
        Fixture fixture = new Fixture(); var input = fixture.add("one", "source\n");
        assertCode("CALIBRATION_SOURCE_DUPLICATE", () -> fixture.scan(List.of(input, input), OPEN));
        assertCode("CALIBRATION_SOURCE_LIMIT", () -> fixture.scan(List.of(), OPEN));
        assertCode("CALIBRATION_SOURCE_LIMIT", () -> fixture.scan(java.util.Collections.nCopies(48, input), OPEN));
        assertCode("CALIBRATION_SOURCE_LIMIT", () -> new NativeLoadedCalibrationSources.ExpectedSource<>("one", "function/one.mcfunction", new byte[65537]));
        var wrong = new NativeLoadedCalibrationSources.ExpectedSource<>("one", "function/other.mcfunction", new byte[0]);
        assertCode("CALIBRATION_SOURCE_MAPPING_MISMATCH", () -> fixture.scan(List.of(wrong), OPEN));
        var excessive = new ArrayList<NativeLoadedCalibrationSources.ExpectedSource<String>>();
        for (int index = 0; index < 17; index++) excessive.add(fixture.add("case" + index, new byte[65536]));
        assertCode("CALIBRATION_SOURCE_LIMIT", () -> fixture.scan(excessive, OPEN));
        assertEquals(0, fixture.opens); assertEquals(0, fixture.views);
        Fixture exact = new Fixture(); var limit = new ArrayList<NativeLoadedCalibrationSources.ExpectedSource<String>>();
        for (int index = 0; index < 16; index++) limit.add(exact.add("case" + index, new byte[65536]));
        var bounded = exact.scan(limit, OPEN);
        assertEquals(1024 * 1024, bounded.sourceBytes()); assertEquals(2L * 1024 * 1024, bounded.readBytes());
        assertEquals(32, exact.opens); assertEquals(32, exact.closes);
    }

    @Test void missingActualSourceFunctionAndPackMembershipRejectWithoutFabricatingObjects() {
        for (String missing : List.of("function", "source", "pack")) {
            Fixture fixture = new Fixture(); var input = fixture.add("one", "source\n");
            switch (missing) {
                case "function" -> fixture.states.get("one").function = null;
                case "source" -> fixture.states.get("one").available = false;
                case "pack" -> fixture.resourcePacks = List.of(new Object());
                default -> throw new AssertionError();
            }
            String code = missing.equals("function") ? "CALIBRATION_FUNCTION_UNAVAILABLE"
                    : missing.equals("source") ? "CALIBRATION_SOURCE_UNAVAILABLE" : "CALIBRATION_SOURCE_CHANGED";
            assertCode(code, () -> fixture.scan(List.of(input), OPEN)); assertEquals(0, fixture.opens);
        }
        Fixture manyPacks = new Fixture(); var input = manyPacks.add("one", "source\n");
        manyPacks.selectedPacks = java.util.Collections.nCopies(257, new Object());
        assertCode("CALIBRATION_SOURCE_LIMIT", () -> manyPacks.scan(List.of(input), OPEN)); assertEquals(0, manyPacks.opens);
    }

    private static void assertCode(String expected, Runnable action) {
        assertEquals(expected, assertThrows(ContractException.class, action::run).code());
    }

    private static final class State {
        private Object function = new Object();
        private Object pack;
        private byte[] bytes;
        private boolean available = true;
        private State(Object pack, byte[] bytes) { this.pack = pack; this.bytes = bytes; }
    }

    private static final class Fixture implements NativeLoadedCalibrationSources.ReadPort<String, Object> {
        private Object resources = new Object();
        private final Object functions = new Object(), repository = new Object(), pack = new Object();
        private List<?> selectedPacks = List.of(new Object());
        private List<?> resourcePacks = List.of(pack);
        private final Map<String, State> states = new LinkedHashMap<>();
        private int views, resolves, opens, closes, delivered;
        private boolean stalled;
        private IOException readFailure;
        private IntConsumer afterRead = ignored -> { }, afterClose = ignored -> { };

        private NativeLoadedCalibrationSources.ExpectedSource<String> add(String id, String bytes) {
            return add(id, bytes.getBytes(StandardCharsets.UTF_8));
        }
        private NativeLoadedCalibrationSources.ExpectedSource<String> add(String id, byte[] bytes) {
            states.put(id, new State(pack, bytes.clone()));
            return new NativeLoadedCalibrationSources.ExpectedSource<>(id, "function/" + id + ".mcfunction", bytes);
        }
        private NativeLoadedCalibrationSources.RawFacts<String, Object> scan(
                List<NativeLoadedCalibrationSources.ExpectedSource<String>> inputs, NativeLoadedCalibrationSources.Checkpoint checkpoint) {
            return NativeLoadedCalibrationSources.scan(this, inputs, checkpoint);
        }
        @Override public void validateMapping(NativeLoadedCalibrationSources.ExpectedSource<String> expected) {
            if (!expected.resourceId().equals("function/" + expected.functionId() + ".mcfunction"))
                throw new ContractException("CALIBRATION_SOURCE_MAPPING_MISMATCH", "합성 fixture mapping 불일치");
        }
        @Override public NativeLoadedCalibrationSources.View view(NativeLoadedCalibrationSources.Checkpoint checkpoint) {
            checkpoint.check(); views++;
            return new NativeLoadedCalibrationSources.View(resources, functions, repository, selectedPacks, List.of("fixture-pack"), resourcePacks);
        }
        @Override public NativeLoadedCalibrationSources.Source<Object> resolve(
                NativeLoadedCalibrationSources.ExpectedSource<String> expected, NativeLoadedCalibrationSources.Checkpoint checkpoint) {
            checkpoint.check(); resolves++;
            State state = states.get(expected.functionId());
            if (state == null || state.function == null) throw new ContractException("CALIBRATION_FUNCTION_UNAVAILABLE", "합성 함수 없음");
            if (!state.available) throw new ContractException("CALIBRATION_SOURCE_UNAVAILABLE", "합성 source 없음");
            return new NativeLoadedCalibrationSources.Source<>(state.function, state.pack, "fixture-pack", () -> open(state));
        }
        private InputStream open(State state) {
            opens++; ByteArrayInputStream bytes = new ByteArrayInputStream(state.bytes);
            return new InputStream() {
                @Override public int read() { throw new AssertionError("유한 chunk read만 허용합니다"); }
                @Override public int read(byte[] target, int offset, int length) throws IOException {
                    assertTrue(length > 0 && length <= 8192);
                    if (readFailure != null) throw readFailure;
                    if (stalled) return 0;
                    int count = bytes.read(target, offset, length);
                    if (count > 0) delivered += count;
                    afterRead.accept(count); return count;
                }
                @Override public void close() { closes++; afterClose.accept(closes); }
            };
        }
    }
}
