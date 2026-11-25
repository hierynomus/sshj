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
package net.schmizz.sshj.common;

import java.security.NoSuchAlgorithmException;

/**
 * Entry point for the Bouncy Castle ML-KEM implementation of {@link SshjKEM}, used by
 * {@link SecurityUtils#getKEM(String)} when the JDK {@code javax.crypto.KEM} API cannot supply ML-KEM
 * (Java 8&ndash;20, or JDK 21+ without a provider that offers it).
 *
 * <p>Bouncy Castle is an optional dependency. This class deliberately refers to no Bouncy Castle types,
 * so it loads and verifies when Bouncy Castle is absent; the code that does use them lives in
 * {@link BouncyCastleKEMImpl}, which is only loaded once {@link #isAvailable()} has confirmed that it
 * can be. Callers must query {@link #isAvailable()} first.</p>
 */
final class BouncyCastleKEM {

    /** BC ML-KEM family name (parameter set inferred from the encoded key). */
    private static final String ML_KEM = "ML-KEM";

    private static final boolean AVAILABLE = probe();

    private BouncyCastleKEM() {
    }

    private static boolean probe() {
        try {
            BouncyCastleKEMImpl.probe();
            return true;
        } catch (Throwable t) {
            // Bouncy Castle absent, or without the ML-KEM classes this implementation was written against
            // (NoClassDefFoundError / LinkageError): the fallback is unavailable.
            return false;
        }
    }

    static boolean isAvailable() {
        return AVAILABLE;
    }

    static SshjKEM create(String algorithm) throws NoSuchAlgorithmException {
        if (!AVAILABLE) {
            throw new NoSuchAlgorithmException(
                    "Bouncy Castle ML-KEM is not available; cannot fall back from javax.crypto.KEM");
        }
        if (!ML_KEM.equals(algorithm)) {
            throw new NoSuchAlgorithmException(
                    "Bouncy Castle KEM fallback only supports " + ML_KEM + ", requested " + algorithm);
        }
        return new BouncyCastleKEMImpl();
    }
}
