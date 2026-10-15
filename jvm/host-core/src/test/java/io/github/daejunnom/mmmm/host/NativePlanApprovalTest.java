package io.github.daejunnom.mmmm.host;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import io.github.daejunnom.mmmm.sdk.Invocation;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Existing host fixtures do not exercise frozen private plan approval or native selector grants. */
final class NativePlanApprovalTest {
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);
    private final ContractJson contracts = new ContractJson();
    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-13T11:59:00Z"));

    @Test void authorityIsClosedBoundedAndRejectsDuplicateOrUnpinnedSteps() throws IOException {
        ObjectNode invocation = fixture(); ObjectNode base = manifest(invocation, false);
        ObjectNode unknown = base.deepCopy().put("callerGrant", true);
        assertThrows(ContractException.class, () -> approval(unknown));
        ObjectNode duplicate = base.deepCopy(); duplicate.withArray("steps").add(duplicate.path("steps").get(0).deepCopy());
        assertThrows(ContractException.class, () -> approval(duplicate));
        ObjectNode duplicateContext = base.deepCopy(); duplicateContext.withArray("contextPins").add(duplicateContext.path("contextPins").get(0).deepCopy());
        assertThrows(ContractException.class, () -> approval(duplicateContext));
        ObjectNode changedPin = base.deepCopy(); first(changedPin, "steps").put("contextDigest", SHA_A);
        assertThrows(ContractException.class, () -> approval(changedPin));
        assertThrows(ContractException.class, () -> approval(base.deepCopy().put("planHash", SHA_A.toUpperCase(java.util.Locale.ROOT))));
        assertThrows(ContractException.class, () -> approval(base.deepCopy().put("expiresAt", "not-an-instant")));
        assertThrows(ContractException.class, () -> new NativePlanApproval(contracts, new byte[NativePlanApproval.MAX_BYTES + 1], clock));
    }

    @Test void frozenPinsAndWholeInvocationOwnershipRemainImmutable() throws IOException {
        ObjectNode wire = fixture(); ObjectNode input = manifest(wire, false); NativePlanApproval approval = approval(input);
        input.put("planHash", SHA_B); first(input, "steps").put("implementationDigest", SHA_B);
        ObjectNode returned = approval.manifest(); returned.put("planHash", SHA_B); first(returned, "steps").put("bindingId", "forged-binding");
        assertEquals(SHA_A, approval.planHash());
        HostSession session = session(wire); Invocation invocation = invocation(wire);
        approval.checkSession(session); approval.checkInvocation(session, invocation, true);
        approval.checkInvocation(session, invocation, true);
        ObjectNode newOperation = wire.deepCopy().put("operationId", "another-operation");
        assertEquals("NATIVE_APPROVAL_REBOUND", assertThrows(ContractException.class,
                () -> approval.checkInvocation(session, invocation(newOperation), true)).code());
        ObjectNode newInvocation = wire.deepCopy().put("invocationId", "another-invocation");
        assertEquals("NATIVE_APPROVAL_REBOUND", assertThrows(ContractException.class,
                () -> approval.checkInvocation(session, invocation(newInvocation), true)).code());
        ObjectNode alteredDeadline = wire.deepCopy().put("deadlineAt", "2026-10-13T12:00:00Z");
        assertEquals("NATIVE_APPROVAL_REBOUND", assertThrows(ContractException.class,
                () -> approval.checkInvocation(session, invocation(alteredDeadline), true)).code());
        ObjectNode changedArguments = wire.deepCopy(); changedArguments.withObject("arguments").put("text", "changed");
        changedArguments.put("argumentsDigest", ContractJson.digest(changedArguments.path("arguments")));
        assertEquals("NATIVE_APPROVAL_MISMATCH", assertThrows(ContractException.class,
                () -> approval.checkInvocation(session, invocation(changedArguments), true)).code());
        ObjectNode changedImplementation = wire.deepCopy().put("implementationDigest", SHA_B);
        assertThrows(ContractException.class, () -> approval.checkInvocation(session, invocation(changedImplementation), true));
    }

    @Test void oneManifestCannotBorrowAnotherContextPrincipalPolicyOrWorld() throws IOException {
        ObjectNode wire = fixture(); NativePlanApproval approval = approval(manifest(wire, false));
        for (String field : Set.of("principalRef", "projectId", "policyRevision", "anchor")) {
            ObjectNode changed = wire.deepCopy(); ObjectNode context = changed.withObject("context");
            context.put(field, "policyRevision".equals(field) ? SHA_B : "anchor".equals(field) ? "eyes" : "changed-owner");
            context.put("contextDigest", ContractJson.contextDigest(context)); changed.put("contextDigest", context.path("contextDigest").asText());
            HostSession other = session(changed);
            assertThrows(ContractException.class, () -> approval.checkInvocation(other, invocation(changed), true));
        }
        ObjectNode changedWorld = wire.deepCopy(); changedWorld.withObject("context").withObject("environment").put("worldId", "another-world");
        repinContext(changedWorld);
        assertThrows(ContractException.class, () -> approval.checkSession(session(changedWorld)));
        HostSession exact = session(wire); exact.close();
        assertEquals("SESSION_EXPIRED", assertThrows(ContractException.class,
                () -> approval.checkInvocation(exact, invocation(wire), true)).code());
    }

    @Test void expirationStopsNewAdmissionAndWritesButRetainsExactAdmittedControls() throws IOException {
        ObjectNode wire = fixture(); HostSession session = session(wire);
        NativePlanApproval approval = approval(manifest(wire, false)); Invocation invocation = invocation(wire);
        approval.checkInvocation(session, invocation, true);
        clock.now = Instant.parse("2026-10-13T12:01:00Z");
        assertDoesNotThrow(() -> approval.checkInvocation(session, invocation, false));
        assertEquals("NATIVE_APPROVAL_EXPIRED", assertThrows(ContractException.class,
                () -> approval.checkInvocation(session, invocation, true)).code());
        NativePlanApproval expired = approval(manifest(wire, false));
        assertEquals("NATIVE_APPROVAL_EXPIRED", assertThrows(ContractException.class,
                () -> expired.checkInvocation(session, invocation, false)).code());
    }

    @Test void differentStepsShareOneOperationButCannotReuseAnInvocationId() throws IOException {
        ObjectNode wire = fixture(); ObjectNode source = manifest(wire, false);
        ObjectNode secondStep = first(source, "steps").deepCopy().put("stepId", "second-step"); source.withArray("steps").add(secondStep);
        NativePlanApproval approval = approval(source); HostSession session = session(wire);
        approval.checkInvocation(session, invocation(wire), true);
        ObjectNode second = wire.deepCopy().put("stepId", "second-step");
        assertEquals("NATIVE_APPROVAL_REBOUND", assertThrows(ContractException.class,
                () -> approval.checkInvocation(session, invocation(second), true)).code());
        second.put("invocationId", "second-invocation");
        assertDoesNotThrow(() -> approval.checkInvocation(session, invocation(second), true));
        ObjectNode anotherOperation = second.deepCopy().put("operationId", "second-operation");
        assertThrows(ContractException.class, () -> approval.checkInvocation(session, invocation(anotherOperation), true));
    }

    @Test void sameImmutableContextCannotMoveOneApprovalIntoAnotherCapabilitySession() throws IOException {
        ObjectNode wire = fixture(); NativePlanApproval approval = approval(manifest(wire, false)); HostSession session = session(wire);
        approval.checkSession(session);
        HostSession another = new HostSession(session.principalRef(), session.epoch(), session.gameInstanceId(), session.side(),
                session.playerId(), Set.of("mmmm:world_read", "mmmm:world_write"), true);
        another.installContext(contracts, wire.path("context"));
        assertEquals("NATIVE_APPROVAL_SESSION_MISMATCH", assertThrows(ContractException.class, () -> approval.checkSession(another)).code());
        assertEquals("NATIVE_APPROVAL_SESSION_MISMATCH", assertThrows(ContractException.class,
                () -> approval.checkInvocation(another, invocation(wire), true)).code());
        assertDoesNotThrow(() -> approval.checkInvocation(session, invocation(wire), true));
    }

    @Test void trustedNativeExecutionRequiresAdmissionAndExactPreparedResourceAndReturnsCopies() throws IOException {
        ObjectNode wire = nativeFixture(); ObjectNode source = manifest(wire, true);
        NativePlanApproval approval = approval(source); HostSession session = session(wire); Invocation invocation = invocation(wire);
        assertThrows(ContractException.class, () -> approval.execution(invocation));
        approval.checkInvocation(session, invocation, true);
        ObjectNode execution = approval.execution(invocation); execution.put("compilerDigest", SHA_B);
        first(execution, "steps").withArray("encoded_commands").removeAll();
        assertEquals(SHA_A, approval.execution(invocation).path("compilerDigest").asText());
        assertEquals(2, first(approval.execution(invocation), "steps").path("encoded_commands").size());
        ObjectNode wrongSource = source.deepCopy(); first(wrongSource, "nativeExecutions").put("preparedChangeSha256", SHA_B);
        NativePlanApproval wrongApproval = approval(wrongSource);
        assertEquals("NATIVE_APPROVAL_MISMATCH", assertThrows(ContractException.class,
                () -> wrongApproval.checkInvocation(session, invocation, true)).code());
    }

    @Test void commandOrderPhaseAndAllOriginalSealedSourceFieldsAreChecked() throws IOException {
        ObjectNode source = manifest(nativeFixture(), true);
        ObjectNode wrongCommand = source.deepCopy(); ObjectNode nativeStep = first(first(wrongCommand, "nativeExecutions"), "steps");
        nativeStep.withArray("encoded_commands").set(0, ContractJson.newObject().put("command", "forged"));
        assertThrows(ContractException.class, () -> approval(wrongCommand));
        ObjectNode wrongDigest = source.deepCopy(); first(first(wrongDigest, "nativeExecutions"), "steps").put("commandDigest", SHA_B);
        assertThrows(ContractException.class, () -> approval(wrongDigest));
        ObjectNode wrongPhase = source.deepCopy(); first(first(wrongPhase, "nativeExecutions"), "steps").put("phase", "cleanup");
        assertThrows(ContractException.class, () -> approval(wrongPhase));
        ObjectNode missingSource = source.deepCopy(); first(first(missingSource, "nativeExecutions"), "steps").remove("owner_prefab_id");
        assertThrows(ContractException.class, () -> approval(missingSource));
        ObjectNode unknownEnum = source.deepCopy(); first(first(unknownEnum, "nativeExecutions"), "steps").withObject("instruction").put("state_type", "arbitrary_type");
        assertThrows(ContractException.class, () -> approval(unknownEnum));
        ObjectNode wrongScalar = source.deepCopy(); first(first(wrongScalar, "nativeExecutions"), "steps").withObject("instruction").put("value", true);
        assertThrows(ContractException.class, () -> approval(wrongScalar));
        ObjectNode lineBreak = source.deepCopy(); ObjectNode brokenStep = first(first(lineBreak, "nativeExecutions"), "steps");
        ArrayNode commands = brokenStep.withArray("encoded_commands"); commands.removeAll(); commands.add("scoreboard objectives add state dummy\nkill @e");
        brokenStep.put("commandDigest", ContractJson.digest(commands));
        assertThrows(ContractException.class, () -> approval(lineBreak));
    }

    @Test void resourceAssociationIsExactAndOneResourceMayNameMultipleAuthorizedSelectors() throws IOException {
        ObjectNode wire = nativeFixture(); ObjectNode source = manifest(wire, true);
        ObjectNode objective = selector("objective"); ObjectNode score = selector("score").put("holder", "holder");
        NativePlanApproval approval = approval(source); HostSession session = session(wire); approval.checkSession(session);
        ObjectNode context = session.context("context-fixture-01");
        assertTrue(approval.resourceAllowed(context, objective)); assertTrue(approval.resourceAllowed(context, score));
        assertFalse(approval.resourceAllowed(context, score.deepCopy().put("holder", "another-holder")));
        assertFalse(approval.resourceAllowed(context, objective.deepCopy().put("objective", "another-objective")));
        ObjectNode changedContext = context.deepCopy(); changedContext.withObject("scope").withArray("resourceIds").removeAll();
        changedContext.put("contextDigest", ContractJson.contextDigest(changedContext));
        assertFalse(approval.resourceAllowed(changedContext, objective));
        ObjectNode duplicate = source.deepCopy(); ObjectNode duplicatedExecution = first(duplicate, "nativeExecutions");
        duplicatedExecution.withArray("resourceTargets").add(association(objective));
        assertThrows(ContractException.class, () -> approval(duplicate));
        ObjectNode missingAssociation = source.deepCopy(); first(missingAssociation, "nativeExecutions").withArray("resourceTargets").removeAll();
        assertThrows(ContractException.class, () -> approval(missingAssociation));
    }

    @Test void nativeExecutorCannotBorrowAnotherApprovedStepsReadFootprint() throws IOException {
        ObjectNode wire = nativeFixture(); wire.withObject("context").withObject("scope").withArray("resourceIds").add("resource-other"); repinContext(wire);
        ObjectNode source = manifest(wire, true); ObjectNode second = first(source, "steps").deepCopy().put("stepId", "second-step");
        second.withArray("resourcesWritten").removeAll().add("resource-other"); source.withArray("steps").add(second);
        ObjectNode secondExecution = first(source, "nativeExecutions").deepCopy().put("stepId", "second-step");
        ObjectNode otherObjective = selector("objective").put("objective", "other").put("resourceId", "resource-other");
        ObjectNode otherScore = selector("score").put("objective", "other").put("holder", "holder").put("resourceId", "resource-other");
        secondExecution.withArray("observedTargets").removeAll().add(observed(otherObjective)).add(observed(otherScore));
        ObjectNode objectiveAssociation = association(otherObjective).put("resourceId", "resource-other");
        ObjectNode scoreAssociation = association(otherScore).put("resourceId", "resource-other");
        secondExecution.withArray("resourceTargets").removeAll().add(objectiveAssociation).add(scoreAssociation);
        ObjectNode secondNativeStep = first(secondExecution, "steps"); secondNativeStep.withObject("instruction").put("objective", "other");
        ArrayNode commands = secondNativeStep.withArray("encoded_commands"); commands.removeAll().add("scoreboard objectives add other dummy").add("scoreboard players set holder other 1");
        secondNativeStep.put("commandDigest", ContractJson.digest(commands)); source.withArray("nativeExecutions").add(secondExecution);
        NativePlanApproval approval = approval(source); HostSession session = session(wire); Invocation first = invocation(wire);
        approval.checkSession(session); approval.checkInvocation(session, first, true); ObjectNode context = session.context(first.contextId());
        assertTrue(approval.resourceAllowed(context, otherObjective), "The frozen plan read footprint contains both steps");
        assertFalse(approval.resourceAllowed(first, context, otherObjective), "A native mutation inspector only sees its exact admitted step");
        assertTrue(approval.resourceAllowed(first, context, selector("objective")));
        ObjectNode secondWire = wire.deepCopy().put("stepId", "second-step").put("invocationId", "second-invocation"); Invocation secondInvocation = invocation(secondWire);
        assertFalse(approval.resourceAllowed(secondInvocation, context, otherObjective), "An unadmitted step cannot inspect with a mutation grant");
        approval.checkInvocation(session, secondInvocation, true); assertTrue(approval.resourceAllowed(secondInvocation, context, otherObjective));
    }

    @Test void unknownBeforeIsOnlyASealedScopedSpawnAttemptAndRemovalRequiresPresentOwnership() throws IOException {
        ObjectNode source = manifest(nativeFixture(), true); ObjectNode execution = first(source, "nativeExecutions"); ObjectNode nativeStep = first(execution, "steps");
        ObjectNode display = ContractJson.newObject().put("kind", "display").put("dimension", "minecraft:overworld").put("tag", "mmmm_fixture").put("entity_kind", "text");
        ArrayNode uuid = display.putArray("uuid"); for (int index = 0; index < 16; index++) uuid.add(0); uuid.set(15, ContractJson.parse(new byte[] {'1'}));
        display.putArray("position").add(1.25).add(64).add(2.5); ArrayNode matrix = display.putArray("matrix"); for (int index = 0; index < 16; index++) matrix.add(index % 5 == 0 ? 1 : 0);
        display.putObject("payload").put("text", "MMMM"); nativeStep.set("instruction", display);
        ArrayNode commands = nativeStep.withArray("encoded_commands"); commands.removeAll().add("execute in minecraft:overworld run summon minecraft:text_display 1.25 64 2.5 {Tags:[\"mmmm_fixture\"]}");
        nativeStep.put("commandDigest", ContractJson.digest(commands));
        ObjectNode selector = ContractJson.newObject().put("kind", "entity").put("dimension", "minecraft:overworld")
                .put("uuid", "00000000-0000-0000-0000-000000000001").put("expectedType", "minecraft:text_display");
        ObjectNode target = observed(selector).put("expectedPresence", "unknown").put("ownerTag", "mmmm_fixture"); execution.withArray("observedTargets").removeAll().add(target); execution.withArray("resourceTargets").removeAll();
        assertDoesNotThrow(() -> approval(source));
        ObjectNode wrongTag = source.deepCopy(); first(first(wrongTag, "nativeExecutions"), "observedTargets").put("ownerTag", "other_tag");
        assertThrows(ContractException.class, () -> approval(wrongTag));
        ObjectNode existingCollision = source.deepCopy(); first(first(existingCollision, "nativeExecutions"), "observedTargets").put("expectedPresence", "present");
        assertThrows(ContractException.class, () -> approval(existingCollision));
        execution.put("phase", "cleanup"); nativeStep.put("phase", "cleanup"); display.put("kind", "display_remove"); display.remove(Set.of("tag", "position", "matrix", "payload"));
        assertThrows(ContractException.class, () -> approval(source));
        target.put("expectedPresence", "present"); assertDoesNotThrow(() -> approval(source));
        target.putNull("ownerTag"); assertThrows(ContractException.class, () -> approval(source));
        ObjectNode unknownState = manifest(nativeFixture(), true); first(first(unknownState, "nativeExecutions"), "observedTargets").put("expectedPresence", "unknown");
        assertThrows(ContractException.class, () -> approval(unknownState));
    }

    @Test void nativeTargetScopeCannotWidenRegionContextWorldOrResourceAuthority() throws IOException {
        ObjectNode wire = nativeFixture(); ObjectNode base = manifest(wire, true); HostSession session = session(wire);
        ObjectNode enlarged = base.deepCopy(); first(first(enlarged, "nativeExecutions").withObject("targetScope"), "regions").withArray("maxExclusive").set(0, ContractJson.parse("11".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        NativePlanApproval widened = approval(enlarged);
        assertThrows(ContractException.class, () -> widened.checkSession(session));
        ObjectNode wrongWorld = base.deepCopy(); first(first(wrongWorld, "nativeExecutions").withObject("targetScope"), "regions").put("worldId", "other-world");
        assertThrows(ContractException.class, () -> approval(wrongWorld).checkSession(session));
        ObjectNode wrongContext = base.deepCopy(); first(first(wrongContext, "nativeExecutions").withObject("targetScope"), "regions").put("contextId", "other-context");
        assertThrows(ContractException.class, () -> approval(wrongContext).checkSession(session));
        ObjectNode moreResources = base.deepCopy(); first(moreResources, "nativeExecutions").withObject("targetScope").withArray("resourceIds").add("unapproved-resource");
        assertThrows(ContractException.class, () -> approval(moreResources).checkSession(session));
        ObjectNode oversizedCoordinate = base.deepCopy(); first(first(oversizedCoordinate, "nativeExecutions").withObject("targetScope"), "regions").withArray("maxExclusive").set(0,
                ContractJson.parse("2147483648".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertThrows(ContractException.class, () -> approval(oversizedCoordinate));
    }

    @Test void displayPoseRetainsExactInvocationPinsAndOnlyAnAlreadyPresentOwnedTarget() throws IOException {
        ObjectNode wire = nativeFixture(); ObjectNode source = poseManifest(wire); NativePlanApproval approval = approval(source);
        Invocation invocation = invocation(wire); ObjectNode pose = first(first(source, "nativeExecutions"), "steps");
        assertDoesNotThrow(() -> NativePlanApproval.validateSealedNativeStep(pose));
        assertThrows(ContractException.class, () -> approval.execution(invocation), "A typed pose is not Invocation admission");
        approval.checkInvocation(session(wire), invocation, true);
        ObjectNode admitted = first(approval.execution(invocation), "steps");
        assertEquals("activate", admitted.path("phase").asText());
        for (String field : Set.of("source_object_id", "source_node_id", "instance_id", "owner_prefab_id")) assertEquals(pose.path(field), admitted.path(field));
        assertEquals(1, admitted.path("encoded_commands").size());
        assertFalse(admitted.path("instruction").has("position")); assertFalse(admitted.path("instruction").has("payload"));
        assertThrows(ContractException.class, () -> approval.activationProof(invocation, admitted, "say fixture"), "Pose phase cannot grant an indirect command body");
    }

    @Test void displayPoseRejectsWrongUuidTypeDimensionTagAndMissingPresentOwnership() throws IOException {
        for (int kind = 0; kind < 8; kind++) {
            ObjectNode source = poseManifest(nativeFixture()); ObjectNode execution = first(source, "nativeExecutions");
            ObjectNode instruction = first(execution, "steps").withObject("instruction"); ObjectNode target = first(execution, "observedTargets");
            switch (kind) {
                case 0 -> instruction.withArray("uuid").set(15, ContractJson.parse(new byte[] {'2'}));
                case 1 -> instruction.put("entity_kind", "item");
                case 2 -> instruction.put("dimension", "minecraft:the_nether");
                case 3 -> instruction.put("tag", "other_owner");
                case 4 -> target.putNull("ownerTag");
                case 5 -> target.put("expectedPresence", "unknown");
                case 6 -> target.put("expectedPresence", "absent");
                default -> target.withObject("selector").put("uuid", "00000000-0000-0000-0000-000000000002");
            }
            assertThrows(ContractException.class, () -> approval(source));
        }
    }

    @Test void displayPoseSourceIsClosedFiniteExactFloat32AndCannotCarryPositionPayloadOrResetInputs() throws IOException {
        for (int kind = 0; kind < 12; kind++) {
            ObjectNode step = first(first(poseManifest(nativeFixture()), "nativeExecutions"), "steps"); ObjectNode instruction = step.withObject("instruction");
            switch (kind) {
                case 0 -> instruction.withArray("matrix").remove(0);
                case 1 -> instruction.withArray("matrix").set(0, ContractJson.newObject().put("value", Double.NaN).get("value"));
                case 2 -> instruction.withArray("matrix").set(0, ContractJson.newObject().put("value", 0.1).get("value"));
                case 3 -> instruction.put("tag", "mmmm_fixture,tag=other");
                case 4 -> instruction.withArray("uuid").set(0, ContractJson.newObject().put("value", 256).get("value"));
                case 5 -> instruction.withArray("uuid").set(0, ContractJson.newObject().put("value", 1.0).get("value"));
                case 6 -> instruction.putArray("position").add(0).add(64).add(0);
                case 7 -> instruction.putObject("payload").put("text", "changed");
                case 8 -> instruction.put("interpolation_duration", 0);
                case 9 -> step.put("phase", "stage");
                case 10 -> { step.withArray("encoded_commands").add(step.path("encoded_commands").get(0).textValue()); step.put("commandDigest", ContractJson.digest(step.path("encoded_commands"))); }
                default -> instruction.withArray("matrix").set(0, ContractJson.newObject().put("value", Double.POSITIVE_INFINITY).get("value"));
            }
            assertThrows(ContractException.class, () -> NativePlanApproval.validateSealedNativeStep(step));
        }
    }

    @Test void activationWithoutItsUniquePlanBoundSourceProofCannotBeAdmitted() throws IOException {
        ActivationFixture fixture = activationFixture(); ObjectNode missing = fixture.manifest().deepCopy();
        first(missing, "nativeExecutions").withArray("nativeActivationProofs").removeAll();
        assertThrows(ContractException.class, () -> approval(missing));
        ObjectNode absentField = fixture.manifest().deepCopy(); first(absentField, "nativeExecutions").remove("nativeActivationProofs");
        assertThrows(ContractException.class, () -> approval(absentField));
        ObjectNode duplicate = fixture.manifest().deepCopy(); ObjectNode execution = first(duplicate, "nativeExecutions");
        execution.withArray("nativeActivationProofs").add(first(execution, "nativeActivationProofs").deepCopy());
        assertThrows(ContractException.class, () -> approval(duplicate));
        ObjectNode duplicateInstruction = fixture.manifest().deepCopy(); ObjectNode duplicateExecution = first(duplicateInstruction, "nativeExecutions");
        duplicateExecution.withArray("steps").add(first(duplicateExecution, "steps").deepCopy());
        assertThrows(ContractException.class, () -> approval(duplicateInstruction));
    }

    @Test void inactiveCommandActivationDoesNotNeedAnIndirectBodyProof() throws IOException {
        ActivationFixture fixture = activationFixture(); ObjectNode source = fixture.manifest().deepCopy(); ObjectNode execution = first(source, "nativeExecutions");
        ObjectNode nativeStep = first(execution, "steps"); nativeStep.withObject("instruction").put("auto", false);
        ArrayNode commands = nativeStep.withArray("encoded_commands"); commands.removeAll().add("execute in minecraft:overworld run data merge block 1 64 1 {auto:0b}");
        nativeStep.put("commandDigest", ContractJson.digest(commands)); execution.withArray("nativeActivationProofs").removeAll();
        NativePlanApproval approval = assertDoesNotThrow(() -> approval(source)); HostSession session = session(fixture.wire()); Invocation invocation = invocation(fixture.wire());
        approval.checkInvocation(session, invocation, true);
        assertFalse(first(approval.execution(invocation), "steps").path("instruction").path("auto").booleanValue());
        assertThrows(ContractException.class, () -> approval.activationProof(invocation, nativeStep, fixture.source()), "Phase alone cannot request an indirect body grant");
        ObjectNode falseProof = first(first(fixture.manifest(), "nativeExecutions"), "nativeActivationProofs").deepCopy();
        falseProof.put("nativeStepDigest", NativeActivationApproval.originalNativeStepDigest(nativeStep)).put("commandDigest", ContractJson.digest(commands));
        execution.withArray("nativeActivationProofs").add(falseProof);
        assertThrows(ContractException.class, () -> approval(source), "A proof for an inactive body is unused authority");
        ObjectNode inventedPhase = first(execution(nativeFixture()), "steps").put("phase", "activate");
        assertThrows(ContractException.class, () -> NativePlanApproval.validateSealedNativeStep(inventedPhase), "The current original compiler emits state initialization in stage");
    }

    @Test void activationProofIsOnlyReturnedAfterExactInvocationAdmissionAndActualRawSourceMatch() throws IOException {
        ActivationFixture fixture = activationFixture(); NativePlanApproval approval = approval(fixture.manifest());
        HostSession session = session(fixture.wire()); Invocation invocation = invocation(fixture.wire());
        assertThrows(ContractException.class, () -> approval.activationProof(invocation, fixture.nativeStep(), fixture.source()));
        approval.checkSession(session); approval.checkInvocation(session, invocation, true);
        ObjectNode proof = approval.activationProof(invocation, fixture.nativeStep(), fixture.source());
        assertEquals(32, proof.size()); assertEquals("mmmm.activation-authority/1", proof.path("format").asText());
        proof.put("sourceBodySha256", SHA_B); first(proof, "effectSelectors").withObject("selector").put("holder", "other-holder");
        ObjectNode returnedAgain = approval.activationProof(invocation, fixture.nativeStep(), fixture.source());
        assertEquals(ContractJson.sha256(fixture.source().getBytes(java.nio.charset.StandardCharsets.UTF_8)), returnedAgain.path("sourceBodySha256").asText());
        assertEquals("holder", first(returnedAgain, "effectSelectors").path("selector").path("holder").asText());
        assertThrows(ContractException.class, () -> approval.activationProof(invocation, fixture.nativeStep(), fixture.source() + " "));
        ObjectNode changedInvocation = fixture.wire().deepCopy().put("invocationId", "unadmitted-invocation");
        assertThrows(ContractException.class, () -> approval.activationProof(invocation(changedInvocation), fixture.nativeStep(), fixture.source()));
        session.close(); assertThrows(ContractException.class, () -> approval.activationProof(invocation, fixture.nativeStep(), fixture.source()));
    }

    @Test void activationAuthorityCannotRebindPlanPinsNativeStepDigestOrPreparedSource() throws IOException {
        ActivationFixture fixture = activationFixture();
        for (String field : Set.of("planHash", "actionDigest", "implementationDigest", "argumentsDigest", "preparedChangeSha256", "contextDigest", "policyRevision",
                "targetArtifactDigest", "compilerDigest", "codecDigest", "nativeStepDigest", "commandDigest")) {
            ObjectNode changed = fixture.manifest().deepCopy(); first(first(changed, "nativeExecutions"), "nativeActivationProofs").put(field, "c".repeat(64));
            assertThrows(ContractException.class, () -> approval(changed), field);
        }
        for (String field : Set.of("stepId", "contextId", "targetProfileId", "sourceObjectId", "instanceId", "ownerPrefabId")) {
            ObjectNode changed = fixture.manifest().deepCopy(); first(first(changed, "nativeExecutions"), "nativeActivationProofs").put(field, "changed-pin");
            assertThrows(ContractException.class, () -> approval(changed), field);
        }
        ObjectNode unknownFlag = fixture.manifest().deepCopy(); first(first(unknownFlag, "nativeExecutions"), "nativeActivationProofs").put("closureComplete", true);
        assertThrows(ContractException.class, () -> approval(unknownFlag));
    }

    @Test void activationEffectsRequireExactMappingResourceAccessAndFullTargetPreconditions() throws IOException {
        ActivationFixture fixture = activationFixture();
        ObjectNode widenedTarget = fixture.manifest().deepCopy(); first(first(first(widenedTarget, "nativeExecutions"), "nativeActivationProofs"), "effectSelectors").withObject("selector").put("holder", "outside-holder");
        assertThrows(ContractException.class, () -> approval(widenedTarget));
        ObjectNode missingWriteScope = fixture.manifest().deepCopy(); first(missingWriteScope, "steps").withArray("resourcesWritten").removeAll();
        assertThrows(ContractException.class, () -> approval(missingWriteScope));
        ObjectNode wrongAccess = fixture.manifest().deepCopy(); first(first(first(wrongAccess, "nativeExecutions"), "nativeActivationProofs"), "effectSelectors").put("access", "read_write");
        assertThrows(ContractException.class, () -> approval(wrongAccess));
        ObjectNode bestEffort = fixture.manifest().deepCopy(); ArrayNode conditions = first(bestEffort, "steps").withArray("preconditions");
        for (JsonNode condition : conditions) if (condition.path("subject").asText().startsWith("native:")) ContractJson.object(condition).put("coverage", "best_effort");
        assertThrows(ContractException.class, () -> approval(bestEffort));
        ObjectNode wrongBeforeDigest = fixture.manifest().deepCopy(); for (JsonNode condition : first(wrongBeforeDigest, "steps").path("preconditions")) {
            if (condition.path("subject").asText().startsWith("native:")) ContractJson.object(condition).put("expected", SHA_B);
        }
        assertThrows(ContractException.class, () -> approval(wrongBeforeDigest));
        ObjectNode missingEvidenceSourcePin = fixture.manifest().deepCopy(); first(first(missingEvidenceSourcePin, "nativeExecutions"), "nativeActivationProofs").withArray("sourceResourcePins").removeAll();
        assertThrows(ContractException.class, () -> approval(missingEvidenceSourcePin));
        for (String kind : Set.of("block_state", "block_entity")) {
            ObjectNode missingControlBefore = fixture.manifest().deepCopy(); String subject = "native:" + ContractJson.digest(blockSelector(kind));
            ArrayNode before = first(missingControlBefore, "steps").withArray("preconditions");
            for (int index = before.size() - 1; index >= 0; index--) if (subject.equals(before.get(index).path("subject").asText())) before.remove(index);
            assertThrows(ContractException.class, () -> approval(missingControlBefore), "Activation control needs its own exact " + kind + " before pin");
            ObjectNode missingObservedControl = fixture.manifest().deepCopy(); ArrayNode observed = first(missingObservedControl, "nativeExecutions").withArray("observedTargets");
            for (int index = observed.size() - 1; index >= 0; index--) if (kind.equals(observed.get(index).path("selector").path("kind").asText())) observed.remove(index);
            assertThrows(ContractException.class, () -> approval(missingObservedControl), "Effect closure cannot substitute for the activation control's actual observation");
        }
    }

    @Test void sealedNativeSourceValidatorIsPureAndCannotSupplyPlanMembership() throws IOException {
        ObjectNode source = first(execution(nativeFixture()), "steps"); String before = source.toString();
        assertDoesNotThrow(() -> NativePlanApproval.validateSealedNativeStep(source)); assertEquals(before, source.toString());
        ObjectNode unsupportedLifecycle = source.deepCopy(); unsupportedLifecycle.withObject("instruction").put("lifecycle", "session");
        assertThrows(ContractException.class, () -> NativePlanApproval.validateSealedNativeStep(unsupportedLifecycle));
        ObjectNode wrongCommands = source.deepCopy(); wrongCommands.withArray("encoded_commands").remove(1); wrongCommands.put("commandDigest", ContractJson.digest(wrongCommands.path("encoded_commands")));
        assertThrows(ContractException.class, () -> NativePlanApproval.validateSealedNativeStep(wrongCommands));
        ObjectNode extraAuthority = source.deepCopy().put("writeApproved", true);
        assertThrows(ContractException.class, () -> NativePlanApproval.validateSealedNativeStep(extraAuthority));
        ObjectNode wire = nativeFixture(); NativePlanApproval approval = approval(manifest(wire, true));
        assertThrows(ContractException.class, () -> approval.execution(invocation(wire)), "Valid source shape alone is not Invocation admission");
    }

    @Test void activationSourceEvidenceNeedsOriginalReadIdsAndCompleteFrozenBeforePins() throws IOException {
        ActivationFixture fixture = activationFixture();
        assertDoesNotThrow(() -> approval(fixture.manifest()), "The after source revision may differ from an original before object pin");
        ObjectNode missingRead = fixture.manifest().deepCopy(); first(missingRead, "steps").withArray("resourcesRead").removeAll();
        assertThrows(ContractException.class, () -> approval(missingRead), "A CAS precondition alone cannot grant an undeclared source read");
        ObjectNode aliasedRead = fixture.manifest().deepCopy(); first(aliasedRead, "steps").withArray("resourcesRead").removeAll().add("resource:native-evidence-fixture");
        assertThrows(ContractException.class, () -> approval(aliasedRead), "ResourceRef identity cannot be rewritten as a subject prefix");
        ObjectNode missingSourceBefore = fixture.manifest().deepCopy(); ArrayNode conditions = first(missingSourceBefore, "steps").withArray("preconditions");
        for (int index = conditions.size() - 1; index >= 0; index--) {
            if (conditions.get(index).path("subject").asText().startsWith("cas:")) conditions.remove(index);
        }
        assertThrows(ContractException.class, () -> approval(missingSourceBefore));
        ObjectNode changedObjectBefore = fixture.manifest().deepCopy();
        for (JsonNode condition : first(changedObjectBefore, "steps").path("preconditions")) {
            if (condition.path("subject").asText().startsWith("owned:")) ContractJson.object(condition).put("expected", SHA_A);
        }
        assertThrows(ContractException.class, () -> approval(changedObjectBefore));
        ObjectNode alteredEvidenceMetadata = fixture.manifest().deepCopy();
        first(first(first(alteredEvidenceMetadata, "nativeExecutions"), "nativeActivationProofs"), "targetEvidenceResources").put("sizeBytes", 11);
        assertThrows(ContractException.class, () -> approval(alteredEvidenceMetadata), "Evidence membership requires the full original ResourceRef");
    }

    private record ActivationFixture(ObjectNode wire, ObjectNode manifest, ObjectNode nativeStep, String source) { }
    private ActivationFixture activationFixture() throws IOException {
        String body = "scoreboard players set holder state 1"; ObjectNode wire = nativeFixture();
        wire.withObject("context").withObject("scope").withArray("resourceIds").add("native-evidence-fixture"); repinContext(wire);
        ObjectNode manifest = manifest(wire, true); ObjectNode planStep = first(manifest, "steps"); planStep.withArray("resourcesRead").add("native-evidence-fixture");
        ObjectNode execution = first(manifest, "nativeExecutions").put("phase", "activate");
        ObjectNode nativeStep = ContractJson.newObject().put("phase", "activate").put("source_object_id", "command-module-fixture").put("source_node_id", "node-fixture")
                .put("instance_id", "instance-fixture").put("owner_prefab_id", "prefab-fixture");
        ObjectNode instruction = nativeStep.putObject("instruction").put("kind", "command_activation").put("dimension", "minecraft:overworld").put("auto", true);
        instruction.putArray("position").add(1).add(64).add(1);
        ArrayNode commands = nativeStep.putArray("encoded_commands").add("execute in minecraft:overworld run data merge block 1 64 1 {auto:1b}");
        String originalStepDigest = ContractJson.digest(nativeStep); nativeStep.put("commandDigest", ContractJson.digest(commands));
        execution.withArray("steps").removeAll().add(nativeStep.deepCopy());
        ObjectNode score = selector("score").put("holder", "holder"); ObjectNode blockState = blockSelector("block_state"); ObjectNode blockEntity = blockSelector("block_entity");
        execution.withArray("observedTargets").removeAll().add(observed(blockState)).add(observed(blockEntity)).add(observed(score));
        execution.withArray("resourceTargets").removeAll().add(association(score));
        ObjectNode evidenceResource = resource("native-evidence-fixture", SHA_B, "application/json", 10);
        ArrayNode preconditions = planStep.withArray("preconditions");
        preconditions.add(condition("resource_hash", "cas:native-evidence-fixture:" + SHA_B, SHA_B));
        preconditions.add(condition("object_revision", "owned:command_module:command-module-fixture:" + SHA_B, SHA_B));
        for (ObjectNode target : java.util.List.of(blockState, blockEntity, score)) preconditions.add(condition("region_snapshot", "native:" + ContractJson.digest(target), SHA_A));
        ObjectNode proof = ContractJson.newObject().put("format", "mmmm.activation-authority/1").put("planHash", SHA_A).put("stepId", wire.path("stepId").asText())
                .put("actionDigest", wire.path("actionDigest").asText()).put("implementationDigest", wire.path("implementationDigest").asText()).put("argumentsDigest", wire.path("argumentsDigest").asText())
                .put("preparedChangeSha256", SHA_A).put("contextId", wire.path("context").path("contextId").asText()).put("contextDigest", wire.path("contextDigest").asText())
                .put("policyRevision", wire.path("context").path("policyRevision").asText()).put("targetProfileId", "target-fixture").put("targetProfileDigest", SHA_A)
                .put("targetArtifactDigest", SHA_A).put("compilerDigest", SHA_A).put("codecDigest", SHA_A).put("producerDigest", "c".repeat(64)).put("registryGeneration", "31")
                .put("activationStepIndex", 10).put("sourceDataStepIndex", 9).put("nativeStepDigest", originalStepDigest).put("commandDigest", ContractJson.digest(commands))
                .put("sourceBodySha256", ContractJson.sha256(body.getBytes(java.nio.charset.StandardCharsets.UTF_8))).put("sourceBodyByteLength", body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length)
                .put("sourceObjectId", "command-module-fixture").put("sourceRevision", SHA_A).put("instanceId", "instance-fixture").put("ownerPrefabId", "prefab-fixture");
        proof.putObject("nativeSourceReceipt").put("digest", SHA_B).put("byteLength", 100); proof.putArray("targetEvidenceResources").add(evidenceResource.deepCopy());
        proof.putArray("sourceObjectPins").add(ContractJson.newObject().put("kind", "command_module").put("objectId", "command-module-fixture").put("revision", SHA_B));
        proof.putArray("sourceResourcePins").add(evidenceResource.deepCopy());
        ObjectNode effect = ContractJson.newObject().put("access", "write"); effect.set("selector", score.deepCopy()); effect.set("resource", resource("resource-state", SHA_A, "application/json", 10));
        proof.putArray("effectSelectors").add(effect); execution.withArray("nativeActivationProofs").add(proof);
        return new ActivationFixture(wire, manifest, nativeStep, body);
    }
    private static ObjectNode blockSelector(String kind) { ObjectNode value = ContractJson.newObject().put("kind", kind).put("dimension", "minecraft:overworld"); value.putArray("position").add(1).add(64).add(1); return value; }
    private static ObjectNode resource(String id, String sha, String mediaType, int size) { return ContractJson.newObject().put("resourceId", id).put("sha256", sha).put("mediaType", mediaType).put("sizeBytes", size); }
    private static ObjectNode condition(String kind, String subject, String expected) { return ContractJson.newObject().put("kind", kind).put("subject", subject).put("expected", expected).put("coverage", "full_target"); }

    private NativePlanApproval approval(ObjectNode value) { return new NativePlanApproval(contracts, value, clock); }
    private Invocation invocation(ObjectNode wire) { return new Invocation(contracts, wire); }
    private HostSession session(ObjectNode wire) {
        ObjectNode context = wire.withObject("context"); JsonNode environment = context.path("environment");
        HostSession session = new HostSession(context.path("principalRef").asText(), environment.path("sessionEpoch").asText(),
                environment.path("gameInstanceId").asText(), environment.path("side").asText(), UUID.randomUUID(), Set.of("mmmm:world_read", "mmmm:world_write"), true);
        session.installContext(contracts, context); return session;
    }
    private ObjectNode manifest(ObjectNode wire, boolean nativeExecution) {
        ObjectNode context = wire.withObject("context"); ObjectNode result = ContractJson.newObject().put("kind", "native_plan_approval")
                .put("protocolVersion", ContractJson.VERSION).put("principalId", context.path("principalRef").asText()).put("projectId", context.path("projectId").asText())
                .put("planId", "plan-fixture").put("planHash", SHA_A).put("policyRevision", context.path("policyRevision").asText()).put("expiresAt", "2026-10-13T12:01:00Z");
        ObjectNode pin = ContractJson.newObject().put("contextId", context.path("contextId").asText()).put("contextDigest", context.path("contextDigest").asText());
        pin.set("environment", context.path("environment").deepCopy()); result.putArray("contextPins").add(pin);
        ObjectNode step = ContractJson.newObject();
        for (String field : Set.of("stepId", "bindingId", "actionId", "actionDigest", "implementationDigest", "argumentsDigest", "contextDigest")) step.set(field, wire.path(field).deepCopy());
        step.put("contextId", context.path("contextId").asText()); step.putArray("resourcesRead"); step.putArray("resourcesWritten"); step.putArray("preconditions");
        if (nativeExecution) step.withArray("resourcesWritten").add("resource-state"); result.putArray("steps").add(step); result.putArray("nativeExecutions");
        if (nativeExecution) result.withArray("nativeExecutions").add(execution(wire)); return result;
    }
    private ObjectNode execution(ObjectNode wire) {
        ObjectNode result = ContractJson.newObject().put("stepId", wire.path("stepId").asText()).put("argumentsDigest", wire.path("argumentsDigest").asText())
                .put("preparedChangeSha256", SHA_A).put("format", "mmmm.native-scene-command/1").put("phase", "stage").put("targetProfileId", "target-fixture")
                .put("targetArtifactDigest", SHA_A).put("compilerDigest", SHA_A).put("codecDigest", SHA_A);
        result.putArray("nativeActivationProofs");
        result.set("targetScope", wire.path("context").path("scope").deepCopy()); ObjectNode selector = selector("objective");
        ObjectNode score = selector("score").put("holder", "holder");
        result.putArray("resourceTargets").add(association(selector)).add(association(score)); result.putArray("observedTargets").add(observed(selector)).add(observed(score));
        ObjectNode instruction = ContractJson.newObject().put("kind", "state_initialize").put("storage", "mmmm:fixture").put("key", "state_key")
                .put("value", 1).put("storage_kind", "scoreboard").put("state_type", "int32").put("lifecycle", "spawn").put("objective", "state").put("holder", "holder");
        ObjectNode step = ContractJson.newObject().put("phase", "stage").put("source_object_id", "object-fixture").putNull("source_node_id")
                .put("instance_id", "instance-fixture").put("owner_prefab_id", "prefab-fixture"); step.set("instruction", instruction);
        ArrayNode commands = step.putArray("encoded_commands"); commands.add("scoreboard objectives add state dummy"); commands.add("scoreboard players set holder state 1");
        step.put("commandDigest", ContractJson.digest(commands)); result.putArray("steps").add(step); return result;
    }
    private static ObjectNode selector(String kind) { return ContractJson.newObject().put("kind", kind).put("objective", "state").put("resourceId", "resource-state"); }
    private ObjectNode poseManifest(ObjectNode wire) {
        // Reuses the private plan/context fixture; this authored shape supplies no actual entity or source proof.
        ObjectNode result = manifest(wire, true); ObjectNode execution = first(result, "nativeExecutions").put("phase", "activate");
        ObjectNode step = first(execution, "steps").put("phase", "activate").put("source_object_id", "clip-fixture").put("source_node_id", "node-fixture");
        ObjectNode instruction = ContractJson.newObject().put("kind", "display_pose").put("dimension", "minecraft:overworld").put("tag", "mmmm_fixture").put("entity_kind", "text");
        ArrayNode uuid = instruction.putArray("uuid"); for (int index = 0; index < 16; index++) uuid.add(index == 15 ? 1 : 0);
        ArrayNode matrix = instruction.putArray("matrix"); for (int index = 0; index < 16; index++) matrix.add(index % 5 == 0 ? 1.0 : 0.0);
        step.set("instruction", instruction); ArrayNode commands = step.putArray("encoded_commands");
        commands.add("execute in minecraft:overworld as 00000000-0000-0000-0000-000000000001 if entity @s[type=minecraft:text_display,tag=mmmm_fixture] run data merge entity @s {transformation:[1f,0f,0f,0f,0f,1f,0f,0f,0f,0f,1f,0f,0f,0f,0f,1f],interpolation_duration:0,start_interpolation:0,teleport_duration:0}");
        step.put("commandDigest", ContractJson.digest(commands));
        ObjectNode selector = ContractJson.newObject().put("kind", "entity").put("dimension", "minecraft:overworld")
                .put("uuid", "00000000-0000-0000-0000-000000000001").put("expectedType", "minecraft:text_display");
        execution.withArray("observedTargets").removeAll().add(observed(selector).put("ownerTag", "mmmm_fixture")); execution.withArray("resourceTargets").removeAll();
        return result;
    }
    private static ObjectNode association(ObjectNode selector) { ObjectNode result = ContractJson.newObject().put("resourceId", "resource-state"); result.set("selector", selector.deepCopy()); return result; }
    private static ObjectNode observed(ObjectNode selector) {
        ObjectNode result = ContractJson.newObject().put("expectedDigest", SHA_A).put("expectedPresence", "present").putNull("ownerTag"); result.set("selector", selector.deepCopy()); return result;
    }
    private static ObjectNode first(ObjectNode value, String field) { return ContractJson.object(value.path(field).get(0)); }
    private static ObjectNode nativeFixture() throws IOException {
        ObjectNode result = fixture(); ObjectNode context = result.withObject("context"); ObjectNode scope = context.withObject("scope"); scope.withArray("resourceIds").add("resource-state");
        ObjectNode region = ContractJson.newObject().put("dimension", "minecraft:overworld").put("contextId", context.path("contextId").asText())
                .put("worldId", context.path("environment").path("worldId").asText()); region.putArray("min").add(0).add(0).add(0); region.putArray("maxExclusive").add(10).add(100).add(10); scope.withArray("regions").add(region);
        repinContext(result); ObjectNode arguments = ContractJson.newObject(); ObjectNode ref = ContractJson.newObject().put("resourceId", "prepared-resource").put("sha256", SHA_A).put("mediaType", "application/json").put("sizeBytes", 123);
        arguments.set("preparedChange", ref); result.set("arguments", arguments); result.put("argumentsDigest", ContractJson.digest(arguments)); return result;
    }
    private static void repinContext(ObjectNode wire) { ObjectNode context = wire.withObject("context"); context.put("contextDigest", ContractJson.contextDigest(context)); wire.put("contextDigest", context.path("contextDigest").asText()); }
    private static ObjectNode fixture() throws IOException {
        Path source = Path.of(System.getProperty("mmmm.checkout"), "examples", "invocation.json");
        try (var input = Files.newInputStream(source)) { return ContractJson.object(ContractJson.parse(input.readNBytes(ContractJson.MAX_BYTES + 1))); }
    }
    private static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant now) { this.now = now; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("Only UTC is used by this test"); return this; }
        @Override public Instant instant() { return now; }
    }
}
