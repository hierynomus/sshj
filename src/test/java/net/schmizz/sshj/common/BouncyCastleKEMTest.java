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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Exercises the Bouncy Castle KEM fallback directly, independent of the JCA
 * {@code javax.crypto.KEM} API path. Validates round-trip encap/decap on JVMs
 * where {@code BouncyCastleKEM.isAvailable()} returns true (i.e. wherever
 * BC PQC is on the classpath, regardless of JDK version).
 */
public class BouncyCastleKEMTest {

    @BeforeAll
    public static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void roundTripProducesMatchingSecret() throws Exception {
        assumeTrue(BouncyCastleKEM.isAvailable(), "Bouncy Castle PQC not on classpath");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", BouncyCastleProvider.PROVIDER_NAME);
        KeyPair kp = kpg.generateKeyPair();

        SshjKEM kem = BouncyCastleKEM.create("ML-KEM");

        SshjKEM.Encapsulated encapsulated = kem.encapsulate(kp.getPublic());
        assertNotNull(encapsulated);
        assertEquals(1088, encapsulated.getCiphertext().length, "ML-KEM-768 ciphertext length");
        assertEquals(32, encapsulated.getSharedSecret().length, "ML-KEM-768 shared secret length");

        byte[] decapsulated = kem.decapsulate(kp.getPrivate(), encapsulated.getCiphertext());
        assertArrayEquals(encapsulated.getSharedSecret(), decapsulated,
                "decapsulated secret must equal encapsulated secret");
    }

    @Test
    public void rejectsUnknownAlgorithm() {
        assumeTrue(BouncyCastleKEM.isAvailable(), "Bouncy Castle PQC not on classpath");
        Throwable t = null;
        try {
            BouncyCastleKEM.create("DHKEM");
        } catch (Throwable thrown) {
            t = thrown;
        }
        assertNotNull(t, "expected NoSuchAlgorithmException");
        assertTrue(t instanceof java.security.NoSuchAlgorithmException, t.toString());
    }
}
