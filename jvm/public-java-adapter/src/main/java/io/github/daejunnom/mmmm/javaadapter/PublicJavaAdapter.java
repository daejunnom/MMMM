package io.github.daejunnom.mmmm.javaadapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import io.github.daejunnom.mmmm.sdk.ActionHandler;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import io.github.daejunnom.mmmm.sdk.LocalContext;
import io.github.daejunnom.mmmm.sdk.OptionalCallbacks;
import io.github.daejunnom.mmmm.sdk.ProviderResult;
import io.github.daejunnom.mmmm.sdk.Registrar;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletionStage;

/** One approved public Java binding, executed by the guarded SDK game queue. */
public final class PublicJavaAdapter {
    /** Platform facts are obtained by the trusted collector, never from a CompatibilityProfile. */
    public record RuntimeTarget(String loader, String modId, String modVersion, String gameVersion, String side) { }
    /** This private host registration is outside the original wire profile; no new public DTO field. */
    public record ReceiverRegistration(Class<?> exactClass, String handleType, String reviewedArgumentPointer) {
        public ReceiverRegistration {
            if (exactClass == null || !exactClass.getName().equals(handleType) || !pointer(reviewedArgumentPointer)) {
                throw failure("UNSUPPORTED_RECEIVER", "Registered receiver requires its exact class and reviewed pointer");
            }
        }
    }
    public interface ProfileApproval {
        void checkProfile(ObjectNode profile, String actualProfileDigest, String actualArtifactDigest, RuntimeTarget actualTarget);
        void checkInterface(ObjectNode observedSupport, ApprovedArtifact.ClassObservation actualClass);
        /** Current source policy may revoke a detected candidate before dispatch. */
        void checkCurrent(String profileDigest, String artifactDigest, Class<?> actualClass);
    }
    public record Policies(ReceiverRegistration receiver, Map<String, Class<?>> scopedTypes,
                           boolean mappingOnlyPrepare) {
        public Policies { scopedTypes = Map.copyOf(scopedTypes); }
        public static Policies scalarsOnly() { return new Policies(null, Map.of(), false); }
    }

    private PublicJavaAdapter() { }

    /** Exact contract/schema, source and signature checks precede a handler candidate. No method is invoked. */
    public static Candidate detect(ContractJson contracts, JsonNode wireProfile, ApprovedArtifact artifact,
                                   ClassLoader loader, ApprovedArtifact.LoadedClassApproval classApproval,
                                   RuntimeTarget target, ProfileApproval approval, Policies policies) {
        contracts.validate("CompatibilityProfile", wireProfile);
        ObjectNode profile = ContractJson.object(wireProfile).deepCopy();
        if (ContractJson.bytes(profile).length > 64 * 1024 || approval == null || target == null || policies == null) {
            throw failure("PROFILE_UNAPPROVED", "A bounded profile and trusted approval are required");
        }
        String profileDigest = ContractJson.digest(profile);
        approval.checkProfile(profile.deepCopy(), profileDigest, artifact.sha256(), target);
        ObjectNode match = ContractJson.object(profile.get("match"));
        if (!match.path("loader").asText().equals(target.loader()) || !match.path("side").asText().equals(target.side())
                || match.has("modId") && !match.path("modId").asText().equals(target.modId())
                || !contains(match.get("supportedGameVersions"), target.gameVersion())
                || !contains(match.get("supportedModVersions"), target.modVersion())
                || !Set.of("server", "client").contains(target.side())) {
            throw failure("VERSION_MISMATCH", "Actual loaded target does not match the exact selected profile");
        }
        ObjectNode binding = ContractJson.object(profile.get("binding"));
        ObjectNode action = ContractJson.object(profile.get("action"));
        if (!"public_java".equals(binding.path("kind").asText()) || !"public_only".equals(binding.path("access").asText())
                || !"invoke_only".equals(binding.path("initialization").asText())
                || !artifact.sha256().equals(action.path("implementationDigest").asText())
                || !target.side().equals(action.path("side").asText())) {
            throw failure("UNSUPPORTED_BINDING", "Binding access, initialization, source pin or queue differs");
        }
        if (!Set.of("none", "queued_only").contains(action.path("cancellation").asText())
                || !"none".equals(action.path("recovery").asText())
                || "pure".equals(action.path("planning").asText()) && !policies.mappingOnlyPrepare()) {
            throw failure("CALLBACK_UNSUPPORTED", "Optional callback guarantees require an explicit approved implementation");
        }
        JsonNode parameterNames = binding.get("parameterTypes");
        if (parameterNames.size() > AdapterLimits.ARGUMENTS || parameterNames.size() != binding.path("arguments").size()) {
            throw failure("INTERFACE_MISMATCH", "Exact method argument count exceeds its bound or differs");
        }
        String ownerName = binding.path("ownerClass").asText();
        ApprovedArtifact.ClassObservation observed = artifact.observe(ownerName, loader, classApproval);
        Class<?> owner = observed.actualClass();
        if (!Modifier.isPublic(owner.getModifiers())) throw failure("UNSUPPORTED_BINDING", "The owning class must be public");
        Class<?>[] parameters = new Class<?>[parameterNames.size()];
        for (int index = 0; index < parameters.length; index++) {
            parameters[index] = parameterType(parameterNames.get(index).asText(), policies.scopedTypes());
            if (!JavaValueCodec.valueType(parameters[index]) && !"handle".equals(binding.path("arguments").get(index).path("kind").asText())) {
                throw failure("UNSUPPORTED_BINDING", "Arbitrary Java classes require registered scoped handles");
            }
        }
        try {
            Method method = owner.getMethod(binding.path("methodName").asText(), parameters);
            boolean isStatic = Modifier.isStatic(method.getModifiers());
            if (method.getDeclaringClass() != owner || method.isBridge() || method.isSynthetic() || method.isVarArgs()
                    || !method.getReturnType().getName().equals(binding.path("returnType").asText())
                    || isStatic != "static".equals(binding.path("receiver").asText())) {
                throw failure("INTERFACE_MISMATCH", "Exact public signature or receiver differs");
            }
            if (!isStatic && (policies.receiver() == null || policies.receiver().exactClass() != owner
                    || !policies.receiver().handleType().equals(binding.path("receiverHandleType").asText()))) {
                throw failure("UNSUPPORTED_RECEIVER", "No exact approved scoped receiver resolver was registered");
            }
            if (isStatic && (binding.has("receiverHandleType") || policies.receiver() != null)) {
                throw failure("UNSUPPORTED_RECEIVER", "Static invocation cannot select a receiver");
            }
            validateReturn(method.getReturnType(), binding.path("resultCodec").asText(), action, policies);
            MethodHandle handle = MethodHandles.publicLookup().unreflect(method);
            ObjectNode support = support(binding, target, policies);
            approval.checkInterface(support.deepCopy(), observed);
            return new Candidate(contracts, action, binding, profileDigest, observed, handle, parameters, isStatic,
                    approval, policies, support);
        } catch (NoSuchMethodException | IllegalAccessException exception) {
            throw failure("INTERFACE_MISMATCH", "The exact public method is not available through public lookup");
        }
    }

    public static final class Candidate implements AutoCloseable {
        private final ContractJson contracts;
        private final ObjectNode descriptor;
        private final ObjectNode binding;
        private final String profileDigest;
        private final String actionDigest;
        private final ApprovedArtifact.ClassObservation source;
        private final MethodHandle method;
        private final Class<?>[] parameters;
        private final boolean isStatic;
        private final ProfileApproval approval;
        private final Policies policies;
        private final ObjectNode support;
        private final JsonSchema input;
        private final JsonSchema output;
        private final Map<String, Job> jobs = new HashMap<>();
        private boolean closed;
        private Candidate(ContractJson contracts, ObjectNode descriptor, ObjectNode binding, String profileDigest,
                          ApprovedArtifact.ClassObservation source, MethodHandle method, Class<?>[] parameters,
                          boolean isStatic, ProfileApproval approval, Policies policies, ObjectNode support) {
            this.contracts = contracts; this.descriptor = descriptor.deepCopy(); this.binding = binding.deepCopy();
            this.profileDigest = profileDigest; actionDigest = ContractJson.digest(descriptor); this.source = source;
            this.method = method; this.parameters = parameters.clone(); this.isStatic = isStatic;
            this.approval = approval; this.policies = policies; this.support = support.deepCopy();
            input = contracts.compileActionSchema(descriptor.get("inputSchema"));
            output = contracts.compileActionSchema(descriptor.get("outputSchema"));
        }
        public ObjectNode descriptor() { return descriptor.deepCopy(); }
        public ObjectNode observedSupport() { return support.deepCopy(); }
        public String artifactDigest() { return source.jarSha256(); }
        public String classDigest() { return source.classSha256(); }
        public String profileDigest() { return profileDigest; }

        /** The trusted host admits provider provenance first; its Registrar still checks the exact action digest. */
        public void register(Registrar registrar) {
            checkCurrent();
            OptionalCallbacks.Prepare prepare = "pure".equals(descriptor.path("planning").asText()) ? (invocation, local) -> {
                verify(invocation); return local.onGameThread(() -> {
                    local.requireGameThread(); local.checkActive(); verify(invocation);
                    mapped(invocation.arguments(), local);
                    return ContractJson.newObject().put("kind", "public_java_mapping_only").put("invocationPerformed", false)
                            .put("actionDigest", actionDigest).put("implementationDigest", source.jarSha256());
                });
            } : null;
            OptionalCallbacks.Poll poll = "job".equals(descriptor.path("completion").asText()) ? this::poll : null;
            OptionalCallbacks.Read read = "read".equals(descriptor.path("effect").asText()) && poll == null ? (request, local) -> {
                checkCurrent();
                if (!request.actionId().equals(descriptor.path("actionId").asText()) || !request.actionDigest().equals(actionDigest)) {
                    throw failure("DEPENDENCY_CHANGED", "Registered read action pin differs");
                }
                return local.onGameThread(() -> callSynchronous(request.arguments(), local));
            } : null;
            ActionHandler execute = (invocation, local) -> {
                verify(invocation);
                return local.onGameThread(() -> execute(invocation, local));
            };
            registrar.action(descriptor(), execute, new OptionalCallbacks(prepare, poll, null, read, null));
        }
        private void verify(Invocation invocation) {
            checkCurrent();
            if (!invocation.actionId().equals(descriptor.path("actionId").asText()) || !invocation.actionDigest().equals(actionDigest)
                    || !invocation.actionContractVersion().equals(descriptor.path("contractVersion").asText())
                    || !invocation.implementationDigest().equals(source.jarSha256())) {
                throw failure("DEPENDENCY_CHANGED", "Invocation does not match the frozen actual Java binding");
            }
        }
        private synchronized void checkCurrent() {
            if (closed) throw failure("BINDING_CLOSED", "Public Java binding has closed");
            approval.checkCurrent(profileDigest, source.jarSha256(), source.actualClass());
        }
        private ProviderResult execute(Invocation invocation, LocalContext local) {
            if (!"job".equals(descriptor.path("completion").asText())) return callSynchronous(invocation.arguments(), local);
            local.requireGameThread(); local.checkActive(); checkCurrent();
            List<Object> arguments = mapped(invocation.arguments(), local);
            Job job;
            synchronized (this) {
                Job previous = jobs.values().stream().filter(value -> value.sameInvocation(invocation, local)).findFirst().orElse(null);
                if (previous != null) {
                    if (!previous.requestDigest.equals(ContractJson.digest(invocation.wire()))) throw failure("IDEMPOTENCY_CONFLICT", "Original Java job invocation changed");
                    return accepted(previous.token);
                }
                if (jobs.size() >= AdapterLimits.JOBS) throw failure("JOB_LIMIT", "Public Java job capacity is exhausted");
                job = new Job(invocation, local, effects());
                jobs.put(job.id, job); // Reserve before the native invocation; never repeat it from poll.
            }
            String token;
            try { token = local.createHandle("job", job.id, String.class); }
            catch (RuntimeException exception) { synchronized (this) { jobs.remove(job.id); } throw exception; }
            job.token = token;
            try { if (!"read".equals(descriptor.path("effect").asText())) local.beginMutation(); }
            catch (RuntimeException exception) { synchronized (this) { jobs.remove(job.id); } throw exception; }
            try {
                Object returned = method.invokeWithArguments(arguments);
                if (!(returned instanceof CompletionStage<?> stage)) throw failure("OUTPUT_INVALID", "API returned no completion stage");
                stage.whenComplete((value, error) -> job.complete(result(value, error, job.effects, null)));
            } catch (VirtualMachineError error) { throw error; }
            catch (Throwable error) { job.complete(result(null, error, job.effects, null)); }
            return accepted(token);
        }
        private ProviderResult callSynchronous(ObjectNode arguments, LocalContext local) {
            local.requireGameThread(); local.checkActive(); checkCurrent();
            List<Object> mapped = mapped(arguments, local);
            if (!"read".equals(descriptor.path("effect").asText())) local.beginMutation();
            try { return result(method.invokeWithArguments(mapped), null, effects(), local); }
            catch (VirtualMachineError error) { throw error; }
            catch (Throwable error) { return result(null, error, effects(), local); }
        }
        private List<Object> mapped(ObjectNode arguments, LocalContext local) {
            JavaValueCodec.checkJson(arguments); ContractJson.validateSchema(input, arguments);
            ObjectNode context = local.executionContext();
            List<Object> result = new ArrayList<>();
            if (!isStatic) result.add(resolve(local, textAt(arguments, policies.receiver().reviewedArgumentPointer()), policies.receiver().handleType(), source.actualClass()));
            JsonNode mappings = binding.path("arguments");
            for (int index = 0; index < parameters.length; index++) {
                JsonNode mapping = mappings.get(index); Class<?> type = parameters[index];
                if ("handle".equals(mapping.path("kind").asText())) {
                    String expected = mapping.path("expectedType").asText();
                    if (!expected.equals(type.getName()) || policies.scopedTypes().get(expected) != type) throw failure("HANDLE_TYPE_MISMATCH", "Exact scoped parameter type is not registered");
                    result.add(resolve(local, textAt(arguments, mapping.path("argumentPointer").asText()), expected, type));
                } else {
                    JsonNode value = switch (mapping.path("kind").asText()) {
                        case "literal" -> mapping.get("value");
                        case "argument" -> at(arguments, mapping.path("pointer").asText());
                        case "context" -> context.get(mapping.path("field").asText());
                        default -> throw failure("UNSUPPORTED_BINDING", "Unsupported binding value kind");
                    };
                    if (value == null || value.isMissingNode()) throw failure("INPUT_INVALID", "Mapped field is absent");
                    if ("argument".equals(mapping.path("kind").asText())) validateArgumentCodec(value, mapping.path("codec").asText());
                    result.add(JavaValueCodec.argument(value, type));
                }
            }
            return result;
        }
        private CompletionStage<ProviderResult> poll(String token, LocalContext local) {
            return local.onGameThread(() -> {
                checkCurrent(); String id = local.resolveHandle(token, "job", String.class); Job job;
                synchronized (this) { job = jobs.get(id); }
                if (job == null || !token.equals(job.token) || !job.principal.equals(local.principalRef())
                        || !job.epoch.equals(local.sessionEpoch()) || !job.contextDigest.equals(ContractJson.contextDigest(local.executionContext()))) {
                    throw failure("HANDLE_SCOPE_MISMATCH", "Public Java job is not owned by the current original scope");
                }
                ProviderResult result = job.result(); return result == null ? accepted(token) : result;
            });
        }
        private ProviderResult result(Object returned, Throwable error, String effects, LocalContext local) {
            if (error != null) {
                String code = error instanceof ContractException exception ? exception.code() : "JAVA_INVOCATION_FAILED";
                return ProviderResult.failed(contracts, code, effects);
            }
            try {
                ObjectNode data;
                if ("registered_handle".equals(binding.path("resultCodec").asText())) {
                    Class<?> type = policies.scopedTypes().get(binding.path("returnType").asText());
                    if (local == null || returned == null || type == null || returned.getClass() != type) throw failure("OUTPUT_INVALID", "Returned scoped value has no exact live type registration");
                    data = ContractJson.newObject().put("handle", createHandle(local, type.getName(), returned, type)).put("handleType", type.getName());
                } else data = JavaValueCodec.result(returned, binding.path("resultCodec").asText());
                ContractJson.validateSchema(output, data);
                return ProviderResult.complete(contracts, data, effects);
            } catch (RuntimeException exception) {
                String code = exception instanceof ContractException contract ? contract.code() : "OUTPUT_INVALID";
                return ProviderResult.failed(contracts, code, effects);
            }
        }
        private ProviderResult accepted(String token) {
            ObjectNode value = ContractJson.newObject().put("contractVersion", ContractJson.VERSION).put("status", "job_accepted")
                    .put("effects", effects()).put("jobHandle", token);
            value.putObject("data"); value.putArray("diagnostics"); value.putArray("artifacts");
            return new ProviderResult(contracts, value);
        }
        private String effects() { return "read".equals(descriptor.path("effect").asText()) ? "none" : "unknown"; }
        @Override public synchronized void close() { closed = true; jobs.clear(); }
    }

    private static final class Job {
        private final String id = "java-job-" + UUID.randomUUID();
        private final String principal;
        private final String epoch;
        private final String contextDigest;
        private final String invocationId;
        private final String bindingId;
        private final String operationId;
        private final String stepId;
        private final String actionDigest;
        private final String implementationDigest;
        private final String argumentsDigest;
        private final String requestDigest;
        private final String effects;
        private String token;
        private ProviderResult completed;
        private Job(Invocation invocation, LocalContext local, String effects) {
            principal = local.principalRef(); epoch = local.sessionEpoch(); contextDigest = invocation.contextDigest(); this.effects = effects;
            invocationId = invocation.invocationId(); bindingId = invocation.bindingId(); operationId = invocation.operationId();
            stepId = invocation.stepId(); actionDigest = invocation.actionDigest(); implementationDigest = invocation.implementationDigest();
            argumentsDigest = invocation.argumentsDigest(); requestDigest = ContractJson.digest(invocation.wire());
        }
        private boolean sameInvocation(Invocation invocation, LocalContext local) {
            return invocationId.equals(invocation.invocationId()) && bindingId.equals(invocation.bindingId())
                    && principal.equals(local.principalRef()) && epoch.equals(local.sessionEpoch());
        }
        private synchronized void complete(ProviderResult value) { if (completed == null) completed = value; }
        private synchronized ProviderResult result() { return completed; }
    }

    private static ObjectNode support(ObjectNode binding, RuntimeTarget target, Policies policies) {
        ObjectNode result = ContractJson.newObject().put("kind", "public_java").put("publicLookupChecked", true)
                .put("initializationPerformed", false).put("threadAffinity", target.side() + "_main");
        ObjectNode signature = result.putObject("signature");
        for (String key : new String[] {"ownerClass", "methodName", "parameterTypes", "returnType", "receiver"}) signature.set(key, binding.get(key).deepCopy());
        if (policies.receiver() == null) result.putNull("receiverResolver"); else result.put("receiverResolver", "host_scoped_handle_v1");
        var types = result.putArray("scopedHandleTypes"); policies.scopedTypes().keySet().stream().sorted().forEach(types::add);
        if (policies.receiver() != null && !policies.scopedTypes().containsKey(policies.receiver().handleType())) types.add(policies.receiver().handleType());
        return result;
    }
    private static void validateReturn(Class<?> type, String codec, ObjectNode action, Policies policies) {
        boolean supported = switch (codec) {
            case "scalar" -> JavaValueCodec.scalar(type);
            case "json_compatible" -> type == List.class || type == Map.class;
            case "completion_stage_json" -> type == CompletionStage.class && "job".equals(action.path("completion").asText());
            case "registered_handle" -> policies.scopedTypes().get(type.getName()) == type;
            default -> false;
        };
        if (!supported || type != CompletionStage.class && !"synchronous".equals(action.path("completion").asText())) {
            throw failure("UNSUPPORTED_BINDING", "Exact return type, completion or result codec is unsupported");
        }
    }
    private static Class<?> parameterType(String name, Map<String, Class<?>> handles) {
        Class<?> primitive = switch (name) {
            case "java.lang.String" -> String.class; case "boolean" -> boolean.class; case "java.lang.Boolean" -> Boolean.class;
            case "int" -> int.class; case "java.lang.Integer" -> Integer.class; case "float" -> float.class;
            case "java.lang.Float" -> Float.class; case "double" -> double.class; case "java.lang.Double" -> Double.class;
            case "java.util.List" -> List.class; case "java.util.Map" -> Map.class; default -> handles.get(name);
        };
        if (primitive == null || !primitive.getName().equals(name)) throw failure("UNSUPPORTED_BINDING", "Parameter type requires an exact registered codec or handle");
        return primitive;
    }
    private static <T> T resolve(LocalContext local, String token, String type, Class<T> javaType) {
        T actual = local.resolveHandle(token, type, javaType);
        if (actual == null || actual.getClass() != javaType) throw failure("HANDLE_TYPE_MISMATCH", "Scoped object differs from its exact approved runtime class");
        return actual;
    }
    private static <T> String createHandle(LocalContext local, String type, Object value, Class<T> javaType) { return local.createHandle(type, javaType.cast(value), javaType); }
    private static JsonNode at(ObjectNode node, String pointer) {
        if (!pointer(pointer)) throw failure("INPUT_INVALID", "Mapping requires a valid bounded JSON pointer");
        JsonNode result;
        try { result = node.at(pointer); } catch (IllegalArgumentException exception) { throw failure("INPUT_INVALID", "Mapping pointer is invalid"); }
        if (result.isMissingNode()) throw failure("INPUT_INVALID", "Mapped argument is absent");
        return result;
    }
    private static String textAt(ObjectNode node, String pointer) {
        JsonNode value = at(node, pointer);
        if (!value.isTextual() || value.textValue().isBlank()) throw failure("HANDLE_TYPE_MISMATCH", "Scoped handle token must be nonempty text");
        return value.textValue();
    }
    private static boolean pointer(String value) { return value != null && value.length() <= 4096 && (value.isEmpty() || value.startsWith("/")); }
    private static boolean contains(JsonNode array, String value) { if (array == null) return false; for (JsonNode item : array) if (item.asText().equals(value)) return true; return false; }
    private static void validateArgumentCodec(JsonNode value, String codec) {
        boolean valid = switch (codec) {
            case "integer" -> value.isIntegralNumber() && value.canConvertToInt();
            case "float" -> value.isNumber() && Double.isFinite(value.doubleValue());
            case "boolean" -> value.isBoolean(); case "quoted_text", "string" -> value.isTextual();
            case "resource_id" -> value.isTextual() && value.asText().matches("[a-z0-9_.-]+:[a-z0-9_./-]+");
            case "json_value" -> true; default -> false;
        };
        if (!valid) throw failure("INPUT_INVALID", "Value does not satisfy its registered argument codec");
    }
    private static ContractException failure(String code, String message) { return new ContractException(code, message); }
}
