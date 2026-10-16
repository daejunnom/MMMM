// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.fixture.provider;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.util.List;

/** Declarations only. The actual host still admits source, descriptor and scope. */
final class FixtureActions {
    static final String READ = "mmmm_fixture:counter_read";
    static final String SET = "mmmm_fixture:counter_set";
    static final String JOB = "mmmm_fixture:counter_job";
    static final String READ_PERMISSION = "mmmm:world_read";
    static final String WRITE_PERMISSION = "mmmm:world_write";
    private FixtureActions() { }

    static ObjectNode read(String implementationDigest) {
        return action(READ, "read", "synchronous", "none", implementationDigest, objectSchema());
    }
    static ObjectNode set(String implementationDigest) {
        return action(SET, "write", "synchronous", "queued_only", implementationDigest, writeSchema(false));
    }
    static ObjectNode job(String implementationDigest) {
        return action(JOB, "write", "job", "cooperative", implementationDigest, writeSchema(true));
    }
    static ObjectNode legacy(String operation, String implementationDigest) {
        ObjectNode action = switch (operation) {
            case "read" -> read(implementationDigest);
            case "set" -> set(implementationDigest);
            case "job" -> job(implementationDigest);
            default -> throw new ContractException("FIXTURE_OPERATION_INVALID", "Unknown fixture declaration");
        };
        action.put("actionId", "mmmm_fixture:legacy_" + operation);
        // Public Java's mapping-only preparation and queued cancellation do
        // not acquire the SDK fixture's actual state or cancellation callback.
        action.put("cancellation", "read".equals(operation) ? "none" : "queued_only");
        return action;
    }
    private static ObjectNode action(String id, String effect, String completion, String cancellation,
                                     String implementationDigest, ObjectNode input) {
        if (implementationDigest == null || !implementationDigest.matches("[a-f0-9]{64}")) {
            throw new ContractException("SOURCE_PIN_REQUIRED", "Exact observed fixture artifact digest is required");
        }
        ObjectNode descriptor = ContractJson.newObject().put("actionId", id).put("contractVersion", ContractJson.VERSION)
                .put("title", "Bounded fixture counter").put("summary", "Reads or changes a session-local counter shared by SDK, public Java and command fixtures")
                .put("semanticKind", "mmmm_fixture:counter_" + (READ.equals(id) ? "read" : JOB.equals(id) ? "job" : "set"))
                .put("side", "server").put("effect", effect).put("planning", "pure").put("completion", completion)
                .put("cancellation", cancellation).put("recovery", "none")
                .put("idempotency", "read".equals(effect) ? "read" : "coordinator_only")
                .put("verificationRequirement", "read".equals(effect) ? "schema_only" : "independent_readback")
                .put("implementationDigest", implementationDigest).put("versionEvidence", "declared");
        descriptor.set("inputSchema", input); descriptor.set("outputSchema", valueSchema());
        descriptor.putArray("requiredContext").add("world").add("dimension").add("executor");
        var permissions = descriptor.putArray("requiredPermissions").add(READ_PERMISSION);
        if (!"read".equals(effect)) permissions.add(WRITE_PERMISSION);
        descriptor.putArray("guarantees").add("bounded_fixture_counter").add("same_server_session_counter");
        descriptor.putArray("limitations").add("Fixture-only state is not a Minecraft block or a world rollback")
                .add("Separately approve the exact legacy fixture artifact and actual loaded callback closure")
                .add("Cancellation never undoes the already applied counter change; late_completion can remain pending")
                .add("Provider completion and returned values require independent target readback");
        return descriptor;
    }
    static ObjectNode objectSchema() {
        ObjectNode schema = ContractJson.newObject().put("type", "object").put("additionalProperties", false);
        schema.putObject("properties"); schema.putArray("required"); return schema;
    }
    static ObjectNode valueSchema() {
        ObjectNode schema = objectSchema();
        schema.withObject("properties").putObject("value").put("type", "integer").put("minimum", 0).put("maximum", 10_000);
        schema.withArray("required").add("value"); return schema;
    }
    private static ObjectNode writeSchema(boolean job) {
        ObjectNode schema = objectSchema(); ObjectNode fields = schema.withObject("properties");
        for (String name : List.of("expected", "value")) {
            fields.putObject(name).put("type", "integer").put("minimum", 0).put("maximum", 10_000);
            schema.withArray("required").add(name);
        }
        var faults = fields.putObject("fault").put("type", "string").putArray("enum");
        faults.add("none").add("before_mutation").add("lost_response");
        if (job) {
            faults.add("late_completion");
            fields.putObject("delayTicks").put("type", "integer").put("minimum", 0).put("maximum", 200);
            schema.withArray("required").add("delayTicks");
        }
        schema.withArray("required").add("fault"); return schema;
    }
}
