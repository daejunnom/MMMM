// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.fixture.provider;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.List;

/**
 * Exact external profile declarations for the SDK-less fixture. The observed
 * JAR digest is an input pin, not approval or loaded-definition authority.
 * Use PublicJavaAdapter.detect with the actual loader/source collector and
 * explicit mapping-only prepare policy; no profile calls a method or creates a receiver.
 */
public final class FixtureProfiles {
    private static final String OWNER = "io.github.daejunnom.mmmm.fixture.legacy.LegacyCounterApi";
    private FixtureProfiles() { }

    public static ObjectNode publicJava(ContractJson contracts, String operation, String observedLegacyJarDigest) {
        ObjectNode action = FixtureActions.legacy(operation, observedLegacyJarDigest);
        ObjectNode profile = profile(operation + "_java", action);
        ObjectNode binding = profile.putObject("binding").put("kind", "public_java")
                .put("ownerClass", OWNER).put("methodName", operation).put("receiver", "static")
                .put("resultCodec", "job".equals(operation) ? "completion_stage_json" : "scalar")
                .put("initialization", "invoke_only").put("access", "public_only")
                .put("returnType", "job".equals(operation) ? "java.util.concurrent.CompletionStage" : "int");
        var types = binding.putArray("parameterTypes").add("java.lang.String").add("java.lang.String");
        var values = binding.putArray("arguments");
        values.addObject().put("kind", "context").put("field", "executorHandle");
        values.addObject().put("kind", "context").put("field", "dimension");
        if (!"read".equals(operation)) {
            for (String field : List.of("expected", "value")) {
                types.add("int"); values.addObject().put("kind", "argument").put("pointer", "/" + field).put("codec", "integer");
            }
            if ("job".equals(operation)) {
                types.add("int"); values.addObject().put("kind", "argument").put("pointer", "/delayTicks").put("codec", "integer");
            }
            types.add("java.lang.String"); values.addObject().put("kind", "argument").put("pointer", "/fault").put("codec", "string");
        }
        contracts.validate("CompatibilityProfile", profile); return profile;
    }

    /** Native command feedback is preserved; it is not the SDK's effect receipt. */
    public static ObjectNode command(ContractJson contracts, String operation, String observedLegacyJarDigest) {
        if (!List.of("read", "set").contains(operation)) {
            throw new ContractException("FIXTURE_OPERATION_INVALID", "Command job observation requires its own native completion issuer");
        }
        ObjectNode action = FixtureActions.legacy(operation, observedLegacyJarDigest)
                .put("actionId", "mmmm_fixture:legacy_command_" + operation);
        action.withArray("limitations").add("Command feedback and return alone do not establish a completed change or equivalent SDK effect receipt");
        ObjectNode output = FixtureActions.objectSchema();
        output.withObject("properties").putObject("returnCode").put("type", "integer");
        output.withObject("properties").putObject("feedback").put("type", "array").put("maxItems", 16)
                .putObject("items").put("type", "string").put("maxLength", 256);
        output.withArray("required").add("returnCode").add("feedback"); action.set("outputSchema", output);
        ObjectNode profile = profile(operation + "_command", action);
        ObjectNode binding = profile.putObject("binding").put("kind", "command")
                .put("executionSource", "context_executor").put("completionProbe", "synchronous_return")
                .put("resultCodec", "command_feedback_v1");
        var parts = binding.putArray("parts");
        parts.addObject().put("kind", "literal").put("value", "mmmm_fixture");
        parts.addObject().put("kind", "literal").put("value", operation);
        if ("set".equals(operation)) {
            for (String field : List.of("expected", "value")) parts.addObject().put("kind", "argument").put("pointer", "/" + field).put("codec", "integer");
            parts.addObject().put("kind", "argument").put("pointer", "/fault").put("codec", "string");
        }
        contracts.validate("CompatibilityProfile", profile); return profile;
    }
    private static ObjectNode profile(String id, ObjectNode action) {
        ObjectNode result = ContractJson.newObject().put("contractVersion", ContractJson.VERSION)
                .put("profileId", "mmmm_fixture:" + id).put("profileVersion", "0.1.0");
        result.putObject("provenance").put("author", "MMMM contributors").put("licenseExpression", "MIT");
        ObjectNode match = result.putObject("match").put("loader", "fabric").put("modId", "mmmm_fixture_legacy").put("side", "server");
        match.putArray("supportedGameVersions").add("26.3"); match.putArray("supportedModVersions").add("0.1.0");
        result.set("action", action); return result;
    }
}
