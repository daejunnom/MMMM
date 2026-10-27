package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** SDK linkage and delegation fixtures; no provider source or game authority is issued here. */
final class RegistrarCompatibilityTest {
    private static final String OLD_REGISTRAR = """
            package io.github.daejunnom.mmmm.sdk;
            import com.fasterxml.jackson.databind.JsonNode;
            @FunctionalInterface
            public interface Registrar {
                void action(JsonNode descriptor, ActionHandler handler, OptionalCallbacks callbacks);
                default void undoAction(String sourceActionId, String undoActionId) {
                    throw new ContractException("RECOVERY_UNSUPPORTED", "This registrar has no provider undo registration");
                }
            }
            """;
    private static final String OLD_PROVIDER = """
            package io.github.daejunnom.mmmm.sdk;
            @FunctionalInterface
            public interface Provider {
                void register(Registrar registrar);
            }
            """;
    private static final String LEGACY_PROVIDER = """
            package interop.legacy;
            import com.fasterxml.jackson.databind.JsonNode;
            import io.github.daejunnom.mmmm.sdk.ActionHandler;
            import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
            import io.github.daejunnom.mmmm.sdk.Provider;
            import io.github.daejunnom.mmmm.sdk.Registrar;
            public final class LegacyProvider implements Provider {
                private final JsonNode descriptor;
                private final ActionHandler handler;
                private final OptionalCallbacks callbacks;
                public LegacyProvider(JsonNode descriptor, ActionHandler handler, OptionalCallbacks callbacks) {
                    this.descriptor = descriptor;
                    this.handler = handler;
                    this.callbacks = callbacks;
                }
                @Override public void register(Registrar registrar) {
                    registrar.action(descriptor, handler, callbacks);
                }
            }
            """;
    private static final String LEGACY_REGISTRAR = """
            package interop.legacy;
            import com.fasterxml.jackson.databind.JsonNode;
            import io.github.daejunnom.mmmm.sdk.ActionHandler;
            import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
            import io.github.daejunnom.mmmm.sdk.Registrar;
            public final class LegacyRegistrar implements Registrar {
                public JsonNode descriptor;
                public ActionHandler handler;
                public OptionalCallbacks callbacks;
                public RuntimeException failure;
                @Override public void action(JsonNode descriptor, ActionHandler handler, OptionalCallbacks callbacks) {
                    if (failure != null) throw failure;
                    this.descriptor = descriptor;
                    this.handler = handler;
                    this.callbacks = callbacks;
                }
            }
            """;

    private static ActionDescriptor descriptor() throws IOException {
        JsonNode action = OriginalFixtures.example("provider-supported.json").path("actions").get(0);
        assertNotNull(action, "The original provider example must contain an action");
        return new ActionDescriptor(new ContractJson(), action);
    }

    @Test
    void originalActionRemainsTheOnlyAbstractMethodAndRawNullStillReachesTheCaller() throws Exception {
        var action = Registrar.class.getMethod("action", JsonNode.class, ActionHandler.class, OptionalCallbacks.class);
        assertEquals(void.class, action.getReturnType());
        assertTrue(Modifier.isAbstract(action.getModifiers()));
        assertTrue(Registrar.class.getMethod("registerAction", ActionDescriptor.class, ActionHandler.class,
                OptionalCallbacks.class).isDefault());
        assertEquals(1, Arrays.stream(Registrar.class.getMethods())
                .filter(method -> method.getDeclaringClass() != Object.class && Modifier.isAbstract(method.getModifiers()))
                .count());

        AtomicInteger calls = new AtomicInteger();
        Registrar existing = (raw, handler, callbacks) -> {
            assertNull(raw);
            assertNull(handler);
            assertNull(callbacks);
            calls.incrementAndGet();
        };
        existing.action(null, null, null);
        assertEquals(1, calls.get());
    }

    @Test
    void typedRegistrationUsesTheExistingBoundaryAndPreservesHandlerAndCallbacks() throws Exception {
        ActionDescriptor descriptor = descriptor();
        ObjectNode expected = descriptor.wire();
        ActionHandler handler = (invocation, context) -> null;
        OptionalCallbacks callbacks = OptionalCallbacks.none();
        AtomicInteger calls = new AtomicInteger();
        Registrar existing = (raw, actualHandler, actualCallbacks) -> {
            assertEquals(expected, raw);
            assertSame(handler, actualHandler);
            assertSame(callbacks, actualCallbacks);
            calls.incrementAndGet();
            ContractJson.object(raw.get("inputSchema")).put("changedByDelegate", true);
            ContractJson.object(raw).put("title", "changed by delegate");
        };

        existing.registerAction(descriptor, handler, callbacks);
        assertEquals(1, calls.get());
        assertEquals(expected, descriptor.wire());

        AtomicInteger nulls = new AtomicInteger();
        Registrar nullReceiver = (raw, actualHandler, actualCallbacks) -> {
            assertEquals(expected, raw);
            assertNull(actualHandler);
            assertNull(actualCallbacks);
            nulls.incrementAndGet();
        };
        nullReceiver.registerAction(descriptor, null, null);
        assertEquals(1, nulls.get());
    }

    @Test
    void typedNullAndRealDelegateFailureAreNotRewrittenOrDispatchedTwice() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        Registrar existing = (raw, handler, callbacks) -> calls.incrementAndGet();
        ContractException invalid = assertThrows(ContractException.class,
                () -> existing.registerAction(null, null, null));
        assertEquals("CONTRACT_INVALID", invalid.code());
        assertEquals(0, calls.get());

        ActionDescriptor descriptor = descriptor();
        RuntimeException original = new IllegalStateException("registration failure");
        Registrar failing = (raw, handler, callbacks) -> {
            calls.incrementAndGet();
            throw original;
        };
        assertSame(original, assertThrows(RuntimeException.class,
                () -> failing.registerAction(descriptor, null, null)));
        assertEquals(1, calls.get());
        assertEquals(0, original.getSuppressed().length);
    }

    /**
     * Existing source fixtures are rebuilt against the current SDK and cannot
     * check linkage of already-compiled callers. These tiny synthetic classes
     * use the previous interface signatures, never a past released artifact.
     */
    @Test
    @Timeout(60)
    void previousInterfaceBytecodeLinksToTheCurrentProviderAndRegistrar(@TempDir Path scratch) throws Exception {
        Path actualTmpRoot = Path.of(System.getProperty("java.io.tmpdir")).toRealPath();
        Path actualScratch = scratch.toRealPath();
        assertTrue(actualScratch.startsWith(actualTmpRoot), "Compiler scratch must stay under the JVM temporary root");
        Path sources = Files.createDirectory(actualScratch.resolve("legacy-source"));
        Path classes = Files.createDirectory(actualScratch.resolve("legacy-classes"));
        Path sdkPackage = Files.createDirectories(sources.resolve("io/github/daejunnom/mmmm/sdk"));
        Path legacyPackage = Files.createDirectories(sources.resolve("interop/legacy"));
        List<Path> files = List.of(
                source(sdkPackage.resolve("Registrar.java"), OLD_REGISTRAR),
                source(sdkPackage.resolve("Provider.java"), OLD_PROVIDER),
                source(legacyPackage.resolve("LegacyProvider.java"), LEGACY_PROVIDER),
                source(legacyPackage.resolve("LegacyRegistrar.java"), LEGACY_REGISTRAR));
        compileOldInterfaces(files, classes);

        ObjectNode source = ContractJson.object(OriginalFixtures.example("provider-supported.json")
                .path("actions").get(0));
        ActionDescriptor typed = new ActionDescriptor(new ContractJson(), source);
        ActionHandler handler = (invocation, context) -> null;
        OptionalCallbacks callbacks = OptionalCallbacks.none();
        try (var loader = new URLClassLoader(new URL[] {classes.toUri().toURL()}, Registrar.class.getClassLoader())) {
            Class<?> oldProviderType = Class.forName("interop.legacy.LegacyProvider", true, loader);
            assertSame(loader, oldProviderType.getClassLoader(), "The provider must come from the owned compiler output");
            assertTrue(Provider.class.isAssignableFrom(oldProviderType));
            Provider oldProvider = (Provider) oldProviderType.getConstructor(JsonNode.class,
                    ActionHandler.class, OptionalCallbacks.class).newInstance(source, handler, callbacks);
            AtomicInteger oldCalls = new AtomicInteger();
            Registrar currentHost = (raw, actualHandler, actualCallbacks) -> {
                assertSame(source, raw);
                assertSame(handler, actualHandler);
                assertSame(callbacks, actualCallbacks);
                oldCalls.incrementAndGet();
            };
            oldProvider.register(currentHost);
            assertEquals(1, oldCalls.get());

            Class<?> oldRegistrarType = Class.forName("interop.legacy.LegacyRegistrar", true, loader);
            assertSame(loader, oldRegistrarType.getClassLoader(), "The registrar must come from the owned compiler output");
            assertTrue(Registrar.class.isAssignableFrom(oldRegistrarType));
            Registrar oldRegistrar = (Registrar) oldRegistrarType.getConstructor().newInstance();
            oldRegistrar.registerAction(typed, handler, callbacks);
            JsonNode received = (JsonNode) oldRegistrarType.getField("descriptor").get(oldRegistrar);
            assertEquals(typed.wire(), received);
            assertSame(handler, oldRegistrarType.getField("handler").get(oldRegistrar));
            assertSame(callbacks, oldRegistrarType.getField("callbacks").get(oldRegistrar));
            ContractJson.object(received).put("title", "changed after registration");
            assertEquals(source, typed.wire());

            RuntimeException failure = new IllegalStateException("legacy failure");
            oldRegistrarType.getField("failure").set(oldRegistrar, failure);
            assertSame(failure, assertThrows(RuntimeException.class,
                    () -> oldRegistrar.registerAction(typed, handler, callbacks)));
        }
    }

    private static Path source(Path path, String contents) throws IOException {
        return Files.writeString(path, contents, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static void compileOldInterfaces(List<Path> sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "A JDK compiler is required for the legacy linkage witness");
        String classpath = Arrays.stream(new Class<?>[] {Registrar.class, Provider.class, JsonNode.class,
                        TreeNode.class, JsonProperty.class})
                .map(RegistrarCompatibilityTest::codeSource)
                .distinct()
                .collect(Collectors.joining(File.pathSeparator));
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(diagnostics, Locale.ROOT,
                StandardCharsets.UTF_8)) {
            List<String> options = List.of("-proc:none", "-encoding", "UTF-8", "-Xmaxerrs", "20",
                    "-Xmaxwarns", "20", "-classpath", classpath, "-d", classes.toString());
            var task = compiler.getTask(null, manager, diagnostics, options, null,
                    manager.getJavaFileObjectsFromPaths(sources));
            boolean compiled = Boolean.TRUE.equals(task.call());
            String summary = diagnostics.getDiagnostics().stream().limit(20)
                    .map(item -> item.getKind() + ":" + item.getCode() + ":" + item.getLineNumber())
                    .collect(Collectors.joining(","));
            assertTrue(compiled, "Legacy signature compiler failed: " + summary);
        }
    }

    private static String codeSource(Class<?> type) {
        try {
            var source = type.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null
                    || !"file".equalsIgnoreCase(source.getLocation().getProtocol())) {
                throw new IllegalStateException("A file-backed compiler classpath is required");
            }
            return Path.of(source.getLocation().toURI()).toAbsolutePath().normalize().toString();
        } catch (java.net.URISyntaxException exception) {
            throw new IllegalStateException("A valid compiler classpath is required", exception);
        }
    }
}
