package io.github.daejunnom.mmmm.javaadapter;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ActionHandler;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import io.github.daejunnom.mmmm.sdk.RegisteredActionRead;
import io.github.daejunnom.mmmm.host.GameThread;
import io.github.daejunnom.mmmm.host.HostAuthority;
import io.github.daejunnom.mmmm.host.HostRuntime;
import io.github.daejunnom.mmmm.host.HostSession;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Existing JSON examples cannot prove actual no-SDK byte loading, static initialization, public lookup or calls. */
final class PublicJavaAdapterTest {
    private static final PublicJavaAdapter.RuntimeTarget TARGET = new PublicJavaAdapter.RuntimeTarget("fabric", "fixture_legacy", "0.1.0", "26.3", "server");
    @TempDir Path temporary;
    private final ContractJson contracts = new ContractJson();
    private ApprovedArtifact artifact;
    private ClassLoader loader;
    private Authority authority;
    @BeforeEach void setUp() throws IOException {
        System.clearProperty("mmmm.javaadapter.fixture.initialized");
        Path jar = temporary.resolve("no-sdk-fixture.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            for (String resource : List.of("org/mmmm/fixture/LegacyApi.class", "org/mmmm/fixture/ReceiverApi.class", "org/mmmm/fixture/ReceiverApi$Child.class")) {
                output.putNextEntry(new JarEntry(resource));
                try (var source = getClass().getResourceAsStream("/" + resource)) {
                    assertNotNull(source); output.write(source.readAllBytes());
                }
                output.closeEntry();
            }
        }
        String actualDigest = ContractJson.sha256(Files.readAllBytes(jar));
        artifact = ApprovedArtifact.open(temporary, jar, observed -> assertEquals(actualDigest, observed));
        loader = artifact.fixtureLoader(); authority = new Authority(actualDigest);
    }

    @Test void discoveryDoesNotInitializeAndRealNonSdkCallRunsOnlyOnTheGuardedQueue() throws Exception {
        ObjectNode profile = profile(); PublicJavaAdapter.Candidate candidate = detect(profile);
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
        assertThrows(ClassNotFoundException.class, () -> Class.forName("io.github.daejunnom.mmmm.sdk.Provider", false, loader));
        assertFalse(candidate.observedSupport().path("initializationPerformed").asBoolean());
        assertTrue(candidate.observedSupport().path("publicLookupChecked").asBoolean());
        Capture registered = register(candidate); FakeContext context = context();
        CompletionStage<ProviderResult> pending = registered.handler.execute(invocation(candidate, arguments("MMMM")), context);
        assertFalse(pending.toCompletableFuture().isDone());
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
        context.drain(); ProviderResult result = pending.toCompletableFuture().join();
        assertEquals("complete", result.status()); assertEquals("MMMM", result.data().path("text").asText());
        assertEquals("none", result.effects()); assertEquals("yes", System.getProperty("mmmm.javaadapter.fixture.initialized"));
        assertEquals(1, calls()); assertNull(registered.callbacks.cancel()); assertNull(registered.callbacks.recover());
        assertNotNull(registered.callbacks.read()); assertNull(registered.callbacks.prepare());
    }

    @Test void anotherActualApiRegistersByProfileWithoutProductionNameBranch() throws Exception {
        ObjectNode profile = profile(); ObjectNode binding = profile.withObject("binding");
        binding.put("methodName", "add").put("returnType", "int").put("resultCodec", "scalar");
        binding.putArray("parameterTypes").add("int").add("int");
        var arguments = binding.putArray("arguments");
        arguments.addObject().put("kind", "argument").put("pointer", "/left").put("codec", "integer");
        arguments.addObject().put("kind", "argument").put("pointer", "/right").put("codec", "integer");
        ObjectNode action = profile.withObject("action").put("actionId", "fixture:legacy_add");
        ObjectNode input = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        input.putObject("properties").putObject("left").put("type", "integer");
        input.withObject("properties").putObject("right").put("type", "integer"); input.putArray("required").add("left").add("right");
        action.set("inputSchema", input); action.set("outputSchema", valueSchema("integer"));
        PublicJavaAdapter.Candidate candidate = detect(profile); Capture registered = register(candidate); FakeContext context = context();
        var pending = registered.handler.execute(invocation(candidate, ContractJson.newObject().put("left", 17).put("right", 25)), context);
        context.drain(); assertEquals(42, pending.toCompletableFuture().join().data().path("value").asInt());
        assertEquals(1, calls());
    }

    @Test void collectorRegistersExactActualDescriptorIntoProductionHostRuntime() throws Exception {
        PublicJavaAdapter.Candidate candidate = detect(profile()); HostQueue queue = new HostQueue();
        HostAuthority live = new HostAuthority() {
            @Override public boolean ready() { return true; }
            @Override public ObjectNode hello() { return ContractJson.newObject(); }
            @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) {
                assertFalse(write); assertEquals(Set.of("diagnostic.read"), permissions);
            }
            @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) { }
        };
        Clock clock = Clock.fixed(Instant.parse("2026-10-13T11:59:00Z"), ZoneOffset.UTC);
        try (HostRuntime runtime = new HostRuntime(contracts, queue, live, (binding, descriptor) -> {
            assertEquals("binding-fixture-01", binding);
            if (descriptor.has("providerId")) assertEquals(candidate.profileDigest(), descriptor.path("origin").path("sourceDigest").asText());
            else {
                assertEquals(artifact.sha256(), descriptor.path("implementationDigest").asText());
                assertEquals(ContractJson.digest(candidate.descriptor()), ContractJson.digest(descriptor));
            }
        }, clock)) {
            ObjectNode provider = example("provider-compatibility.json").put("bindingId", "binding-fixture-01");
            provider.withObject("origin").put("sourceId", "fixture:legacy_java_echo").put("sourceDigest", candidate.profileDigest());
            provider.putArray("actions"); runtime.registerProvider(provider);
            candidate.register((descriptor, handler, callbacks) -> runtime.register("binding-fixture-01", descriptor, handler, callbacks));
            HostSession session = new HostSession("principal-fixture", "epoch-fixture-01", "game-fixture-01", "server", UUID.randomUUID(), Set.of("diagnostic.read"), false);
            session.installContext(contracts, example("execution-context.json"));
            Invocation invocation = invocation(candidate, arguments("MMMM"));
            var first = runtime.dispatch(session, invocation); var duplicate = runtime.dispatch(session, invocation);
            assertFalse(first.toCompletableFuture().isDone()); queue.drain();
            assertEquals("MMMM", first.toCompletableFuture().join().data().path("text").asText());
            assertEquals(first.toCompletableFuture().join().wire(), duplicate.toCompletableFuture().join().wire()); assertEquals(1, calls());
            ObjectNode request = ContractJson.newObject().put("contextId", invocation.contextId()).put("bindingId", invocation.bindingId())
                    .put("actionId", invocation.actionId()).put("actionDigest", invocation.actionDigest()); request.set("arguments", arguments("read"));
            var read = runtime.registeredRead(session, new RegisteredActionRead(contracts, request), clock.instant().plusSeconds(10));
            queue.drain(); assertEquals("read", read.toCompletableFuture().join().data().path("text").asText()); assertEquals(2, calls());
            assertEquals("complete", runtime.operation(session, invocation.invocationId()).path("result").path("status").asText());
        }
    }

    @Test void readonlyCompatibilityProbePinsRealInterfaceAndReadsOnlyActualRegisteredInventory() throws Exception {
        ObjectNode profile = scalarProfile(); ObjectNode environment = example("execution-context.json").withObject("environment").deepCopy();
        String profileDigest = ContractJson.digest(profile); String interfaceDigest = scalarInterfaceDigest(profile);
        try (CompatibilityInterfaceProbe probe = CompatibilityInterfaceProbe.detect(contracts, ContractJson.bytes(profile),
                profileDigest, "approval-fixture-scalar", interfaceDigest, artifact, loader, authority::checkClass,
                TARGET, authority, environment)) {
            assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
            assertEquals(profileDigest, probe.profileDigest()); assertEquals(artifact.sha256(), probe.artifactDigest());
            assertEquals(interfaceDigest, probe.interfaceDigest());
            ObjectNode bindingMaterial = ContractJson.newObject().put("kind", "mmmm-compatibility-binding/1")
                    .put("profileDigest", profileDigest).put("interfaceDigest", interfaceDigest);
            bindingMaterial.set("environment", environment);
            assertEquals("compat-" + ContractJson.digest(bindingMaterial), probe.bindingId());
            ObjectNode provider = probe.providerDescriptor();
            assertEquals("compatibility", provider.path("registrationMode").asText());
            assertEquals("local_profile", provider.path("origin").path("kind").asText());
            assertEquals("approval-fixture-scalar", provider.path("origin").path("sourceId").asText());
            assertEquals(profileDigest, provider.path("origin").path("sourceDigest").asText());
            HostQueue queue = new HostQueue();
            HostAuthority live = new HostAuthority() {
                @Override public boolean ready() { return true; }
                @Override public ObjectNode hello() { return ContractJson.newObject(); }
                @Override public void check(HostSession session, ObjectNode context, Set<String> permissions, boolean write) { assertFalse(write); }
                @Override public void checkPreconditions(HostSession session, ObjectNode context, ObjectNode arguments) { }
            };
            Clock clock = Clock.fixed(Instant.parse("2026-10-13T11:59:00Z"), ZoneOffset.UTC);
            try (HostRuntime runtime = new HostRuntime(contracts, queue, live, (binding, descriptor) -> {
                assertEquals(probe.bindingId(), binding);
                if (descriptor.has("providerId")) assertEquals(profileDigest, descriptor.path("origin").path("sourceDigest").asText());
                else assertEquals(artifact.sha256(), descriptor.path("implementationDigest").asText());
            }, clock)) {
                runtime.registerProvider(probe.registrationDescriptor());
                probe.register((descriptor, handler, callbacks) -> runtime.register(probe.bindingId(), descriptor, handler, callbacks));
                ObjectNode registered = ContractJson.object(runtime.inventory().path("providers").get(0));
                String before = runtime.inventory().path("inventoryRevision").asText();
                ObjectNode observed = probe.inspect(registered, environment);
                assertEquals(provider, observed.get("registeredProvider"));
                assertEquals(profileDigest, observed.path("profileDigest").asText());
                assertEquals(interfaceDigest, CompatibilityInterfaceProbe.interfaceDigest(observed.withObject("interface")));
                assertFalse(observed.path("interface").has("evidence"));
                assertEquals("server_main", observed.path("interface").path("support").path("threadAffinity").asText());
                assertTrue(observed.path("interface").path("support").path("scopedHandleTypes").isEmpty());
                assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
                assertEquals(before, runtime.inventory().path("inventoryRevision").asText());
                ObjectNode changed = registered.deepCopy().put("providerVersion", "0.2.0");
                assertEquals("REGISTRATION_CHANGED", assertThrows(ContractException.class, () -> probe.inspect(changed, environment)).code());
                ObjectNode anotherEpoch = environment.deepCopy().put("sessionEpoch", "epoch-other");
                assertEquals("REGISTRATION_CHANGED", assertThrows(ContractException.class, () -> probe.inspect(registered, anotherEpoch)).code());
                authority.enabled = false;
                assertEquals("PROFILE_UNAPPROVED", assertThrows(ContractException.class, () -> probe.inspect(registered, environment)).code());
                assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
                authority.enabled = true;
                ObjectNode context = example("execution-context.json");
                HostSession session = new HostSession("principal-fixture", "epoch-fixture-01", "game-fixture-01", "server",
                        UUID.randomUUID(), Set.of("diagnostic.read"), false);
                session.installContext(contracts, context);
                ObjectNode request = ContractJson.newObject().put("contextId", context.path("contextId").asText())
                        .put("bindingId", probe.bindingId()).put("actionId", profile.path("action").path("actionId").asText())
                        .put("actionDigest", ContractJson.digest(profile.get("action")));
                request.set("arguments", ContractJson.newObject().put("left", 17).put("right", 25));
                var pending = runtime.registeredRead(session, new RegisteredActionRead(contracts, request), clock.instant().plusSeconds(10));
                assertFalse(pending.toCompletableFuture().isDone());
                assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
                queue.drain(); assertEquals(42, pending.toCompletableFuture().join().data().path("value").asInt());
                assertEquals(1, calls());
            }
        }
    }

    @Test void readonlyProbeRejectsProfileAndInterfacePinTamperingBeforeInitialization() throws Exception {
        ObjectNode profile = scalarProfile(); ObjectNode environment = example("execution-context.json").withObject("environment").deepCopy();
        String actualProfile = ContractJson.digest(profile); String actualInterface = scalarInterfaceDigest(profile);
        assertEquals("PROFILE_UNAPPROVED", assertThrows(ContractException.class, () -> CompatibilityInterfaceProbe.detect(contracts,
                ContractJson.bytes(profile), "0".repeat(64), "approval-fixture-scalar", actualInterface,
                artifact, loader, authority::checkClass, TARGET, authority, environment)).code());
        assertEquals("INTERFACE_MISMATCH", assertThrows(ContractException.class, () -> CompatibilityInterfaceProbe.detect(contracts,
                ContractJson.bytes(profile), actualProfile, "approval-fixture-scalar", "0".repeat(64),
                artifact, loader, authority::checkClass, TARGET, authority, environment)).code());
        ObjectNode handles = profile.deepCopy(); handles.withObject("binding").put("receiver", "registered_handle")
                .put("receiverHandleType", "org.mmmm.fixture.ReceiverApi");
        assertEquals("UNSUPPORTED_BINDING", assertThrows(ContractException.class, () -> CompatibilityInterfaceProbe.detect(contracts,
                ContractJson.bytes(handles), ContractJson.digest(handles), "approval-fixture-scalar", actualInterface,
                artifact, loader, authority::checkClass, TARGET, authority, environment)).code());
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
    }

    @Test void unsupportedParameterAndUnregisteredReceiverNeverInitializeOrConstruct() throws Exception {
        ObjectNode unsupported = profile(); ObjectNode binding = unsupported.withObject("binding").put("methodName", "rejectsThread");
        binding.putArray("parameterTypes").add("java.lang.Thread");
        assertEquals("UNSUPPORTED_BINDING", assertThrows(ContractException.class, () -> detect(unsupported)).code());
        ObjectNode receiver = profile(); receiver.withObject("binding").put("ownerClass", "org.mmmm.fixture.ReceiverApi")
                .put("receiver", "registered_handle").put("receiverHandleType", "org.mmmm.fixture.ReceiverApi");
        assertEquals("UNSUPPORTED_RECEIVER", assertThrows(ContractException.class, () -> detect(receiver)).code());
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
    }

    @Test void approvedFactoryCreatesScopedHandleAndExplicitReceiverCannotCrossScope() throws Exception {
        Class<?> type = Class.forName("org.mmmm.fixture.ReceiverApi", false, loader);
        ObjectNode factory = profile(); factory.withObject("binding").put("ownerClass", type.getName()).put("methodName", "create")
                .put("returnType", type.getName()).put("resultCodec", "registered_handle");
        factory.withObject("action").put("actionId", "fixture:receiver_factory");
        factory.withObject("binding").putArray("parameterTypes"); factory.withObject("binding").putArray("arguments");
        factory.withObject("action").set("outputSchema", handleSchema(type.getName()));
        PublicJavaAdapter.Policies handlePolicies = new PublicJavaAdapter.Policies(null, Map.of(type.getName(), type), false);
        PublicJavaAdapter.Candidate maker = detect(factory, handlePolicies); Capture factoryRegistration = register(maker); FakeContext context = context();
        var created = factoryRegistration.handler.execute(invocation(maker, arguments("unused")), context); context.drain();
        String token = created.toCompletableFuture().join().data().path("handle").asText(); assertFalse(token.isBlank());
        ObjectNode receiver = profile(); receiver.withObject("binding").put("ownerClass", type.getName()).put("receiver", "registered_handle").put("receiverHandleType", type.getName());
        receiver.withObject("action").put("actionId", "fixture:receiver_echo");
        receiver.withObject("action").withObject("inputSchema").withObject("properties").putObject("receiver").put("type", "string");
        receiver.withObject("action").withObject("inputSchema").withArray("required").add("receiver");
        PublicJavaAdapter.Policies receiverPolicies = new PublicJavaAdapter.Policies(new PublicJavaAdapter.ReceiverRegistration(type, type.getName(), "/receiver"), Map.of(type.getName(), type), false);
        PublicJavaAdapter.Candidate method = detect(receiver, receiverPolicies); Capture registration = register(method);
        ObjectNode input = arguments("MMMM").put("receiver", token);
        var invoked = registration.handler.execute(invocation(method, input), context); context.drain();
        assertEquals("receiver:MMMM", invoked.toCompletableFuture().join().data().path("text").asText());
        FakeContext other = context(); var denied = registration.handler.execute(invocation(method, input), other); other.drain();
        assertThrows(java.util.concurrent.CompletionException.class, () -> denied.toCompletableFuture().join());
    }

    @Test void exactSourceProfileSignatureAndRevocationCannotBeSelfDeclared() throws Exception {
        ObjectNode changed = profile(); changed.withObject("action").put("implementationDigest", "0".repeat(64));
        assertEquals("UNSUPPORTED_BINDING", assertThrows(ContractException.class, () -> detect(changed)).code());
        ObjectNode signature = profile(); signature.withObject("binding").put("returnType", "java.lang.String");
        assertEquals("INTERFACE_MISMATCH", assertThrows(ContractException.class, () -> detect(signature)).code());
        assertThrows(ContractException.class, () -> PublicJavaAdapter.detect(contracts, profile(), artifact, ClassLoader.getSystemClassLoader(), authority::checkClass, TARGET, authority, PublicJavaAdapter.Policies.scalarsOnly()));
        PublicJavaAdapter.Candidate candidate = detect(profile()); Capture registration = register(candidate); authority.enabled = false;
        assertEquals("PROFILE_UNAPPROVED", assertThrows(ContractException.class, () -> registration.handler.execute(invocation(candidate, arguments("MMMM")), context())).code());
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
    }

    @Test void actualCompletionStageIsInvokedOnceAndPollNeverRestartsTheApi() throws Exception {
        ObjectNode profile = profile(); profile.withObject("binding").put("methodName", "later").put("returnType", "java.util.concurrent.CompletionStage").put("resultCodec", "completion_stage_json");
        profile.withObject("action").put("completion", "job");
        PublicJavaAdapter.Candidate candidate = detect(profile); Capture registration = register(candidate); FakeContext context = context();
        Invocation invocation = invocation(candidate, arguments("MMMM"));
        var invoked = registration.handler.execute(invocation, context); context.drain();
        ProviderResult accepted = invoked.toCompletableFuture().join(); assertEquals("job_accepted", accepted.status());
        var duplicate = registration.handler.execute(invocation, context); context.drain();
        assertEquals(accepted.jobHandle(), duplicate.toCompletableFuture().join().jobHandle());
        var conflict = registration.handler.execute(invocation(candidate, arguments("changed")), context); context.drain();
        var conflictFailure = assertThrows(java.util.concurrent.CompletionException.class, () -> conflict.toCompletableFuture().join());
        assertEquals("IDEMPOTENCY_CONFLICT", ((ContractException) conflictFailure.getCause()).code());
        var pending = registration.callbacks.poll().poll(accepted.jobHandle(), context); context.drain();
        assertEquals("job_accepted", pending.toCompletableFuture().join().status()); assertEquals(1, calls());
        Class.forName("org.mmmm.fixture.LegacyApi", false, loader).getMethod("finishLater", String.class).invoke(null, "completed");
        var finished = registration.callbacks.poll().poll(accepted.jobHandle(), context); context.drain();
        assertEquals("completed", finished.toCompletableFuture().join().data().path("text").asText()); assertEquals(1, calls());
        FakeContext other = context(); var denied = registration.callbacks.poll().poll(accepted.jobHandle(), other); other.drain();
        assertThrows(java.util.concurrent.CompletionException.class, () -> denied.toCompletableFuture().join());
    }

    @Test void dispatchExceptionDoesNotErasePossibleWriteEffects() throws Exception {
        ObjectNode profile = profile(); profile.withObject("binding").put("methodName", "throwsAfterDispatch");
        profile.withObject("action").put("effect", "write").put("idempotency", "coordinator_only");
        PublicJavaAdapter.Candidate candidate = detect(profile); Capture registration = register(candidate); FakeContext context = context();
        var result = registration.handler.execute(invocation(candidate, arguments("MMMM")), context); context.drain();
        assertEquals("failed", result.toCompletableFuture().join().status()); assertEquals("unknown", result.toCompletableFuture().join().effects());
        assertTrue(context.mutation); assertEquals(1, calls());
    }

    @Test void missingOrExplicitMappingOnlyPrepareNeverExecutesTheApi() throws Exception {
        ObjectNode profile = profile(); profile.withObject("action").put("planning", "pure");
        assertEquals("CALLBACK_UNSUPPORTED", assertThrows(ContractException.class, () -> detect(profile)).code());
        PublicJavaAdapter.Candidate candidate = detect(profile, new PublicJavaAdapter.Policies(null, Map.of(), true));
        Capture registration = register(candidate); FakeContext context = context();
        var prepared = registration.callbacks.prepare().prepare(invocation(candidate, arguments("MMMM")), context);
        assertFalse(prepared.toCompletableFuture().isDone()); context.drain();
        assertFalse(prepared.toCompletableFuture().join().path("invocationPerformed").asBoolean(true));
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
    }

    @Test void registeredHandleResultCannotSubstituteAnOverridingSubclass() throws Exception {
        Class<?> type = Class.forName("org.mmmm.fixture.ReceiverApi", false, loader);
        ObjectNode profile = profile(); profile.withObject("binding").put("ownerClass", type.getName()).put("methodName", "child")
                .put("returnType", type.getName()).put("resultCodec", "registered_handle");
        profile.withObject("binding").putArray("parameterTypes"); profile.withObject("binding").putArray("arguments");
        profile.withObject("action").set("outputSchema", handleSchema(type.getName()));
        PublicJavaAdapter.Candidate candidate = detect(profile, new PublicJavaAdapter.Policies(null, Map.of(type.getName(), type), false));
        Capture registration = register(candidate); FakeContext context = context();
        var result = registration.handler.execute(invocation(candidate, arguments("unused")), context); context.drain();
        assertEquals("failed", result.toCompletableFuture().join().status());
        assertEquals("OUTPUT_INVALID", result.toCompletableFuture().join().wire().path("diagnostics").get(0).path("code").asText());
        assertEquals(0, context.handles.size());
    }

    @Test void queuedPrepareRechecksRevokedApprovalBeforeReturningMetadata() throws Exception {
        ObjectNode profile = profile(); profile.withObject("action").put("planning", "pure");
        PublicJavaAdapter.Candidate candidate = detect(profile, new PublicJavaAdapter.Policies(null, Map.of(), true));
        Capture registration = register(candidate); FakeContext context = context();
        var pending = registration.callbacks.prepare().prepare(invocation(candidate, arguments("MMMM")), context);
        authority.enabled = false; context.drain();
        assertThrows(java.util.concurrent.CompletionException.class, () -> pending.toCompletableFuture().join());
        assertNull(System.getProperty("mmmm.javaadapter.fixture.initialized"));
    }

    @Test void completedJobsRemainBoundedAndAreNeverEvictedIntoARepeatedCall() throws Exception {
        ObjectNode profile = profile(); profile.withObject("binding").put("methodName", "later").put("returnType", "java.util.concurrent.CompletionStage").put("resultCodec", "completion_stage_json");
        profile.withObject("action").put("completion", "job");
        PublicJavaAdapter.Candidate candidate = detect(profile); Capture registration = register(candidate); FakeContext context = context();
        Class.forName("org.mmmm.fixture.LegacyApi", false, loader).getMethod("finishLater", String.class).invoke(null, "complete");
        String firstToken = null; Invocation first = null;
        for (int index = 0; index < AdapterLimits.JOBS; index++) {
            ObjectNode wire = invocation(candidate, arguments("MMMM")).wire().put("invocationId", "invocation-bound-" + index).put("operationId", "operation-bound-" + index);
            Invocation original = new Invocation(contracts, wire); var result = registration.handler.execute(original, context); context.drain();
            String token = result.toCompletableFuture().join().jobHandle();
            if (index == 0) { firstToken = token; first = original; }
            var polled = registration.callbacks.poll().poll(token, context); context.drain();
            assertEquals("complete", polled.toCompletableFuture().join().status());
        }
        assertEquals(AdapterLimits.JOBS, calls());
        ObjectNode excess = invocation(candidate, arguments("MMMM")).wire().put("invocationId", "invocation-excess").put("operationId", "operation-excess");
        var denied = registration.handler.execute(new Invocation(contracts, excess), context); context.drain();
        var failure = assertThrows(java.util.concurrent.CompletionException.class, () -> denied.toCompletableFuture().join());
        assertEquals("JOB_LIMIT", ((ContractException) failure.getCause()).code());
        assertNotNull(first); var duplicate = registration.handler.execute(first, context); context.drain();
        assertEquals(firstToken, duplicate.toCompletableFuture().join().jobHandle()); assertEquals(AdapterLimits.JOBS, calls());
    }

    private PublicJavaAdapter.Candidate detect(ObjectNode profile) { return detect(profile, PublicJavaAdapter.Policies.scalarsOnly()); }
    private PublicJavaAdapter.Candidate detect(ObjectNode profile, PublicJavaAdapter.Policies policies) {
        return PublicJavaAdapter.detect(contracts, profile, artifact, loader, authority::checkClass, TARGET, authority, policies);
    }
    private ObjectNode profile() throws IOException {
        ObjectNode result = example("compat-public-java.json"); result.withObject("action").put("implementationDigest", artifact.sha256()).put("planning", "unsupported");
        return result;
    }
    private ObjectNode scalarProfile() throws IOException {
        ObjectNode profile = profile(); ObjectNode binding = profile.withObject("binding");
        binding.put("methodName", "add").put("returnType", "int").put("resultCodec", "scalar");
        binding.putArray("parameterTypes").add("int").add("int");
        var mappings = binding.putArray("arguments");
        mappings.addObject().put("kind", "argument").put("pointer", "/left").put("codec", "integer");
        mappings.addObject().put("kind", "argument").put("pointer", "/right").put("codec", "integer");
        ObjectNode input = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        input.putObject("properties").putObject("left").put("type", "integer");
        input.withObject("properties").putObject("right").put("type", "integer");
        input.putArray("required").add("left").add("right");
        profile.withObject("action").set("inputSchema", input); profile.withObject("action").set("outputSchema", valueSchema("integer"));
        return profile;
    }
    private String scalarInterfaceDigest(ObjectNode profile) {
        ObjectNode support = ContractJson.newObject().put("kind", "public_java").put("publicLookupChecked", true)
                .put("initializationPerformed", false).put("threadAffinity", "server_main");
        ObjectNode signature = support.putObject("signature");
        for (String key : new String[] {"ownerClass", "methodName", "parameterTypes", "returnType", "receiver"}) {
            signature.set(key, profile.path("binding").get(key).deepCopy());
        }
        support.putNull("receiverResolver"); support.putArray("scopedHandleTypes");
        ObjectNode material = ContractJson.newObject().put("kind", "mmmm-interface-observation/1").put("side", "server")
                .put("loader", "fabric").put("targetGameVersion", "26.3").put("modId", "fixture_legacy")
                .put("modVersion", "0.1.0").put("hostProtocolVersion", ContractJson.VERSION).put("implementationDigest", artifact.sha256());
        material.set("support", support); return ContractJson.digest(material);
    }
    private Invocation invocation(PublicJavaAdapter.Candidate candidate, ObjectNode arguments) throws IOException {
        ObjectNode value = example("invocation.json"); ObjectNode action = candidate.descriptor();
        value.put("actionId", action.path("actionId").asText()).put("actionDigest", ContractJson.digest(action)).put("implementationDigest", artifact.sha256());
        value.set("arguments", arguments); value.put("argumentsDigest", ContractJson.digest(arguments));
        return new Invocation(contracts, value);
    }
    private static ObjectNode example(String name) throws IOException {
        Path root = Path.of(System.getProperty("mmmm.checkout"));
        return ContractJson.object(ContractJson.parse(Files.readAllBytes(root.resolve("examples").resolve(name))));
    }
    private FakeContext context() throws IOException { return new FakeContext(example("execution-context.json")); }
    private int calls() throws ReflectiveOperationException { return (Integer) Class.forName("org.mmmm.fixture.LegacyApi", false, loader).getMethod("calls").invoke(null); }
    private static ObjectNode arguments(String value) { return ContractJson.newObject().put("text", value); }
    private static Capture register(PublicJavaAdapter.Candidate candidate) { Capture captured = new Capture(); candidate.register((descriptor, handler, callbacks) -> { captured.handler = handler; captured.callbacks = callbacks; }); return captured; }
    private static ObjectNode valueSchema(String type) {
        ObjectNode schema = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        schema.putObject("properties").putObject("value").put("type", type); schema.putArray("required").add("value"); return schema;
    }
    private static ObjectNode handleSchema(String type) {
        ObjectNode schema = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        schema.putObject("properties").putObject("handle").put("type", "string");
        schema.withObject("properties").putObject("handleType").put("const", type); schema.putArray("required").add("handle").add("handleType"); return schema;
    }
    private static final class Capture { private ActionHandler handler; private OptionalCallbacks callbacks; }
    private static final class HostQueue implements GameThread {
        private final Queue<Runnable> pending = new ArrayDeque<>(); private boolean active;
        @Override public boolean isSameThread() { return active; }
        @Override public void execute(Runnable callback) { pending.add(callback); }
        private void drain() { active = true; try { while (!pending.isEmpty()) pending.remove().run(); } finally { active = false; } }
    }
    private static final class Authority implements PublicJavaAdapter.ProfileApproval {
        private final String source; private boolean enabled = true;
        private Authority(String source) { this.source = source; }
        private void checkClass(Class<?> actual, ClassLoader actualLoader, String artifact, String classDigest) {
            assertEquals(source, artifact); assertEquals(actual.getClassLoader(), actualLoader); assertEquals(64, classDigest.length());
        }
        @Override public void checkProfile(ObjectNode profile, String digest, String artifact, PublicJavaAdapter.RuntimeTarget target) {
            if (!enabled || !source.equals(artifact)) throw new ContractException("PROFILE_UNAPPROVED", "Fixture policy denied the observed source");
            assertEquals(ContractJson.digest(profile), digest); assertEquals(TARGET, target);
        }
        @Override public void checkInterface(ObjectNode support, ApprovedArtifact.ClassObservation actual) { assertEquals(source, actual.jarSha256()); }
        @Override public void checkCurrent(String profile, String artifact, Class<?> actual) {
            if (!enabled || !source.equals(artifact)) throw new ContractException("PROFILE_UNAPPROVED", "Fixture policy revoked the source");
        }
    }
    private static final class FakeContext implements LocalContext {
        private final ObjectNode context;
        private final Queue<Runnable> queue = new ArrayDeque<>();
        private final Map<String, Object> handles = new HashMap<>();
        private final Map<String, Class<?>> types = new HashMap<>();
        private boolean inQueue; private boolean mutation;
        private FakeContext(ObjectNode context) { this.context = context; }
        @Override public String principalRef() { return context.path("principalRef").asText(); }
        @Override public String sessionEpoch() { return context.path("environment").path("sessionEpoch").asText(); }
        @Override public ObjectNode executionContext() { return context.deepCopy(); }
        @Override public boolean cancellationRequested() { return false; }
        @Override public void requirePermission(String value) { }
        @Override public void checkActive() { }
        @Override public void requireGameThread() { if (!inQueue) throw new ContractException("WRONG_THREAD", "Fixture requires queued target access"); }
        @Override public <T> CompletionStage<T> onGameThread(Supplier<T> callback) {
            CompletableFuture<T> result = new CompletableFuture<>(); queue.add(() -> {
                try { inQueue = true; result.complete(callback.get()); } catch (RuntimeException error) { result.completeExceptionally(error); }
                finally { inQueue = false; }
            }); return result;
        }
        private void drain() { while (!queue.isEmpty()) queue.remove().run(); }
        @Override public <T> String createHandle(String kind, T value, Class<T> type) {
            requireGameThread(); String token = "handle-" + handles.size(); handles.put(token, value); types.put(token, type); return token;
        }
        @Override public <T> T resolveHandle(String token, String kind, Class<T> type) {
            requireGameThread(); if (types.get(token) != type || !handles.containsKey(token)) throw new ContractException("HANDLE_SCOPE_MISMATCH", "Unknown fixture scope"); return type.cast(handles.get(token));
        }
        @Override public void recordEffect(ObjectNode value) { requireGameThread(); }
        @Override public void beginMutation() { requireGameThread(); mutation = true; }
    }
}
