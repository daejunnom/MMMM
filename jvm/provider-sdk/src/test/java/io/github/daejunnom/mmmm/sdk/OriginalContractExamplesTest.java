package io.github.daejunnom.mmmm.sdk;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class OriginalContractExamplesTest {
    private final ContractJson contracts = new ContractJson();

    @TestFactory
    List<DynamicTest> everyIndexedOriginalExampleMatchesItsDeclaredDefinition() throws IOException {
        ObjectNode index = ContractJson.object(OriginalFixtures.read("tests/example-index.json"));
        assertFalse(index.isEmpty(), "The original example index must not silently produce zero tests");
        List<DynamicTest> tests = new ArrayList<>();
        var entries = index.fields();
        while (entries.hasNext()) {
            var entry = entries.next();
            String file = entry.getKey();
            String definition = entry.getValue().asText();
            tests.add(DynamicTest.dynamicTest(definition + " / " + file, () -> {
                ObjectNode example = OriginalFixtures.example(file);
                assertDoesNotThrow(() -> contracts.validate(definition, example));
            }));
        }
        return tests;
    }

    @Test
    void originalInvocationConstructsWithoutRewritingItsDigestsOrExpiredFixtureDeadline() throws IOException {
        ObjectNode original = OriginalFixtures.example("invocation.json");
        Invocation invocation = assertDoesNotThrow(() -> new Invocation(contracts, original));
        assertEquals(original, invocation.wire());
    }

    @Test
    void unknownContractDefinitionFailsClosed() throws IOException {
        ObjectNode original = OriginalFixtures.example("invocation.json");
        ContractException failure = assertThrows(ContractException.class,
                () -> contracts.validate("UnregisteredDefinition", original));
        assertEquals("CONTRACT_UNKNOWN", failure.code());
    }

    @Test
    void originalInvocationRejectsWrongVersionAndUndeclaredRootFields() throws IOException {
        ObjectNode wrongVersion = OriginalFixtures.example("invocation.json");
        wrongVersion.put("contractVersion", "0.1.0");
        assertThrows(ContractException.class, () -> contracts.validate("Invocation", wrongVersion));

        ObjectNode undeclaredField = OriginalFixtures.example("invocation.json");
        undeclaredField.put("platformReceiver", "must-not-enter-the-wire-contract");
        assertThrows(ContractException.class, () -> contracts.validate("Invocation", undeclaredField));
    }
}
