/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.sshj.test;

import net.schmizz.sshj.transport.kex.MLKEM768X25519SHA256;

/**
 * Conditions for tests that need a working ML-KEM-768 implementation, for use with
 * {@code @DisabledIf} / {@code @EnabledIf}. ML-KEM is only available when a JCA provider supplies it
 * (JDK 24+) or Bouncy Castle is on the classpath, so on other runtimes the key exchange is not offered.
 */
public final class MLKEM {
    /** {@code @DisabledIf} condition: no working ML-KEM-768 implementation is reachable. */
    public static final String UNSUPPORTED = "com.hierynomus.sshj.test.MLKEM#isUnsupported";

    /** {@code @EnabledIf} condition: a working ML-KEM-768 implementation is reachable. */
    public static final String SUPPORTED = "com.hierynomus.sshj.test.MLKEM#isSupported";

    public static final String REASON = "Requires an ML-KEM-768 implementation (JDK 24+ or Bouncy Castle)";

    private MLKEM() {
    }

    public static boolean isSupported() {
        return MLKEM768X25519SHA256.isSupported();
    }

    public static boolean isUnsupported() {
        return !isSupported();
    }
}
