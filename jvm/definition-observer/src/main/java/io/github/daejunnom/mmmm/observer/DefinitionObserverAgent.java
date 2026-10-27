// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.jar.JarFile;

/**
 * Startup linkage and bounded coverage probes for the Rust JVMTI agent.
 * This Java agent installs no transformer and modifies no game or JDK code.
 * The controlled launcher separately pins the JDK, both agents, startup order,
 * approved native components and disabled dynamic attach. Probe coverage alone
 * neither proves a closed transformer chain nor enables an MMMM write profile.
 */
public final class DefinitionObserverAgent {
    private static final int MAX_AGENT_JAR_BYTES = 16 * 1024 * 1024;
    // JDK 25 libinstrument uses a Windows _MAX_PATH-sized platform string.
    // Leave room for its terminating NUL, including on this fixed-JDK launcher.
    private static final int MAX_NATIVE_JAR_NAME_BYTES = 259;
    // The bootstrap search remains valid for the lifetime of this JVM.
    private static JarFile retainedBootstrapJar;

    private DefinitionObserverAgent() { }

    public static void premain(String options, Instrumentation instrumentation) {
        if (Runtime.version().feature() != 25 || instrumentation == null
                || options != null && !options.isEmpty() && !options.equals("protocol=mmmm.definition-observer/1")) {
            throw unavailable();
        }
        try {
            appendOwnBootstrapJar(instrumentation);
            // Both the fixed main and fixture owner resolve from the appended
            // bootstrap JAR. No system-loader nested class or retained Agent
            // state is shared across a different runtime package identity.
            if (DefinitionStartupFixtures.class.getClassLoader() != null
                    || DefinitionObserverBridge.class.getClassLoader() != null) throw unavailable();
            DefinitionStartupFixtures.runOnce();
        } catch (Exception | LinkageError exception) {
            // premain failure stops this controlled JVM startup. It cannot be silently ignored
            // like a ClassFileTransformer exception, or reported as an observed definition.
            throw new IllegalStateException("MMMM_DEFINITION_OBSERVER_STARTUP_UNAVAILABLE", exception);
        }
    }

    private static void appendOwnBootstrapJar(Instrumentation instrumentation) throws Exception {
        if (retainedBootstrapJar != null) throw unavailable();
        var location = DefinitionObserverAgent.class.getProtectionDomain().getCodeSource();
        if (location == null || !"file".equals(location.getLocation().getProtocol())) throw unavailable();
        Path jarPath = Path.of(location.getLocation().toURI()).toAbsolutePath();
        Path workingDirectory = Path.of("").toAbsolutePath().normalize();
        Path nativeName = bootstrapJarName(jarPath, workingDirectory);
        // InstrumentationImpl passes getName(), not this JarFile's open handle,
        // to libinstrument. An ASCII relative name avoids encoding the shared
        // absolute prefix again. The launcher keeps the selected original JAR
        // pinned; this representation neither copies it nor adds a new source.
        if (!Files.isSameFile(nativeName, jarPath)) throw unavailable();
        var opened = new JarFile(nativeName.toFile(), true);
        boolean appended = false;
        try {
            if (!Path.of(opened.getName()).equals(nativeName)
                    || !Files.isSameFile(Path.of(opened.getName()), jarPath)
                    || !bootstrapJarName(jarPath, workingDirectory).equals(nativeName)) throw unavailable();
            instrumentation.appendToBootstrapClassLoaderSearch(opened);
            if (!Files.isSameFile(nativeName, jarPath)
                    || !bootstrapJarName(jarPath, workingDirectory).equals(nativeName)) throw unavailable();
            retainedBootstrapJar = opened; appended = true;
        } finally { if (!appended) opened.close(); }
    }

    /** A path representation only; actual launch pins remain the source authority. */
    static Path bootstrapJarName(Path jarPath, Path workingDirectory) throws Exception {
        if (jarPath == null || workingDirectory == null || !jarPath.isAbsolute()
                || !workingDirectory.isAbsolute() || !jarPath.equals(jarPath.normalize())
                || !workingDirectory.equals(workingDirectory.normalize())
                || !jarPath.getFileSystem().equals(workingDirectory.getFileSystem())
                || !jarPath.getRoot().equals(workingDirectory.getRoot())) throw unavailable();
        requirePlainDirectories(workingDirectory);
        requirePlainDirectories(jarPath.getParent());
        var attributes = Files.readAttributes(jarPath, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.isSymbolicLink() || attributes.isOther()
                || attributes.size() <= 0 || attributes.size() > MAX_AGENT_JAR_BYTES) throw unavailable();
        Path relative = workingDirectory.relativize(jarPath);
        String name = relative.toString();
        if (relative.isAbsolute() || name.isEmpty() || name.length() > MAX_NATIVE_JAR_NAME_BYTES)
            throw unavailable();
        for (int index = 0; index < name.length(); index++) {
            char character = name.charAt(index);
            if (character < 0x20 || character > 0x7e) throw unavailable();
        }
        if (!Files.isSameFile(workingDirectory.resolve(relative), jarPath)) throw unavailable();
        return relative;
    }

    private static void requirePlainDirectories(Path directory) throws Exception {
        if (directory == null) throw unavailable();
        Path cursor = directory.getRoot();
        requirePlainDirectory(cursor);
        for (Path component : directory) {
            cursor = cursor.resolve(component);
            requirePlainDirectory(cursor);
        }
    }

    private static void requirePlainDirectory(Path directory) throws Exception {
        var attributes = Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        // Windows junction/reparse entries report isOther(), even when they
        // also carry the directory attribute. Check both before native reopen.
        if (!attributes.isDirectory() || attributes.isSymbolicLink() || attributes.isOther()) throw unavailable();
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("MMMM_DEFINITION_OBSERVER_STARTUP_UNAVAILABLE");
    }
}
