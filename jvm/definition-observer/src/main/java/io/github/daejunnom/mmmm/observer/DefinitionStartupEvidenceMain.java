// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
package io.github.daejunnom.mmmm.observer;

import java.io.IOException;

/**
 * Prints the one-time verified MMMMABI2/v1 startup frame for the controlled Rust launcher.
 * Its 24-byte header contains lengths for the MMMMABI1/v1 frame and the nonempty
 * MMMMDEF1 and MMMMSAM1 evidence sections.
 * The launcher bounds process time, drains both outputs, and accepts at most 18 MiB.
 */
public final class DefinitionStartupEvidenceMain {
    private static final int MIN_FRAME_BYTES = 62; // 24-byte header + 36-byte legacy frame + 1 + 1.
    private static final int MAX_FRAME_BYTES = 18 * 1024 * 1024;

    private DefinitionStartupEvidenceMain() { }

    public static void main(String[] args) throws IOException {
        if (args == null || args.length != 0) {
            throw new IOException("MMMM_DEFINITION_STARTUP_ARGUMENTS_INVALID");
        }
        if (DefinitionStartupEvidenceMain.class.getClassLoader() != null
                || DefinitionStartupFixtures.class.getClassLoader() != null
                || DefinitionObserverBridge.class.getClassLoader() != null) {
            throw new IOException("MMMM_DEFINITION_STARTUP_BOOTSTRAP_UNAVAILABLE");
        }
        byte[] frame = DefinitionStartupFixtures.takeVerifiedFrame();
        if (frame == null || frame.length < MIN_FRAME_BYTES || frame.length > MAX_FRAME_BYTES) {
            throw new IOException("MMMM_DEFINITION_STARTUP_FRAME_INVALID");
        }
        System.out.write(frame);
        System.out.flush();
        if (System.out.checkError()) {
            throw new IOException("MMMM_DEFINITION_STARTUP_OUTPUT_FAILED");
        }
    }
}
