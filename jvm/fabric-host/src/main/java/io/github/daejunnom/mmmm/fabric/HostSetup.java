package io.github.daejunnom.mmmm.fabric;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.daejunnom.mmmm.host.AnonymousBridge;
import io.github.daejunnom.mmmm.host.HostDispatcher;
import io.github.daejunnom.mmmm.sdk.ContractException;
import io.github.daejunnom.mmmm.sdk.ContractJson;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Set;

/** Public local setup metadata. Its requested scope and paths never create an authority grant. */
record HostSetup(Path executable, String executableSha256, Path dataRoot, String projectId,
                 ObjectNode scope, String hostArtifactDigest) {
    HostSetup { scope = scope.deepCopy(); }
    @Override public ObjectNode scope() { return scope.deepCopy(); }

    static HostSetup read(ContractJson contracts, Path source) {
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) throw invalid();
        try (var input = Files.newInputStream(source)) {
            byte[] bytes = input.readNBytes(256 * 1024 + 1); if (bytes.length > 256 * 1024) throw invalid();
            ObjectNode value = ContractJson.object(ContractJson.parse(bytes));
            HostDispatcher.exactFields(value, Set.of("executable", "executableSha256", "dataRoot", "projectId", "scope", "hostArtifactDigest"));
            String projectId = HostDispatcher.string(value, "projectId");
            String executableSha = HostDispatcher.string(value, "executableSha256");
            String artifactSha = HostDispatcher.string(value, "hostArtifactDigest");
            if (!projectId.matches("[a-z0-9][a-z0-9._:-]{0,127}") || !executableSha.matches("[a-f0-9]{64}") || !artifactSha.matches("[a-f0-9]{64}")) throw invalid();
            ObjectNode scope = ContractJson.object(value.path("scope")); contracts.validate("Scope", scope);
            if (!projectId.equals(scope.path("projectId").asText())) throw invalid();
            Path executable = Path.of(HostDispatcher.string(value, "executable"));
            Path dataRoot = Path.of(HostDispatcher.string(value, "dataRoot"));
            if (!executable.isAbsolute() || !dataRoot.isAbsolute() || executable.toString().startsWith("\\\\") || dataRoot.toString().startsWith("\\\\")) throw invalid();
            if (!Files.isDirectory(dataRoot, LinkOption.NOFOLLOW_LINKS) || !dataRoot.normalize().equals(dataRoot.toRealPath())) throw invalid();
            AnonymousBridge.verifyExecutable(executable, executableSha);
            return new HostSetup(executable.normalize(), executableSha, dataRoot.normalize(), projectId, scope, artifactSha);
        } catch (IOException | java.nio.file.InvalidPathException exception) { throw invalid(); }
    }
    private static ContractException invalid() { return new ContractException("HOST_SETUP_INVALID", "Public MMMM host setup is missing or does not match its closed contract"); }
}
