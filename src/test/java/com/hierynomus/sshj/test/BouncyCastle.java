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

/**
 * Detects whether Bouncy Castle is on the classpath, for use in {@code @DisabledIf} / {@code @EnabledIf}
 * conditions on tests that exercise features which depend on Bouncy Castle (it is an optional dependency).
 * <p>
 * Usage: {@code @DisabledIf(BouncyCastle.ABSENT)}
 */
public final class BouncyCastle {
    /** Condition for {@code @DisabledIf}: disables the test when Bouncy Castle is not available. */
    public static final String ABSENT = "com.hierynomus.sshj.test.BouncyCastle#isAbsent";

    public static final String REASON = "Requires Bouncy Castle, which is not on the classpath";

    private BouncyCastle() {
    }

    public static boolean isPresent() {
        try {
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    public static boolean isAbsent() {
        return !isPresent();
    }
}
