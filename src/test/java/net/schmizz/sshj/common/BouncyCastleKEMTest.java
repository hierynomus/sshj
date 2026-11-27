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

import com.hierynomus.sshj.test.BouncyCastle;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the Bouncy Castle KEM fallback directly, independent of the JCA
 * {@code javax.crypto.KEM} API path. Validates round-trip encap/decap on JVMs
 * where {@code BouncyCastleKEM.isAvailable()} returns true (i.e. wherever
 * BC PQC is on the classpath, regardless of JDK version).
 */
@DisabledIf(value = BouncyCastle.ABSENT, disabledReason = BouncyCastle.REASON)
public class BouncyCastleKEMTest {

    @Test
    public void roundTripProducesMatchingSecret() throws Exception {
        assertTrue(BouncyCastleKEM.isAvailable(),
                "Bouncy Castle is present, so its ML-KEM fallback must be usable (BC API may have changed)");

        KeyPair kp = SecurityUtils.getKeyPairGenerator("ML-KEM-768").generateKeyPair();

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
        assertTrue(BouncyCastleKEM.isAvailable(),
                "Bouncy Castle is present, so its ML-KEM fallback must be usable (BC API may have changed)");
        Throwable t = null;
        try {
            BouncyCastleKEM.create("DHKEM");
        } catch (Throwable thrown) {
            t = thrown;
        }
        assertNotNull(t, "expected NoSuchAlgorithmException");
        assertTrue(t instanceof java.security.NoSuchAlgorithmException, t.toString());
    }

    @Test
    public void encapsulateRejectsUnparseablePublicKey() {
        assertThrows(GeneralSecurityException.class,
                () -> BouncyCastleKEM.create("ML-KEM").encapsulate(new FakePublicKey(new byte[] {1, 2, 3})));
    }

    @Test
    public void decapsulateRejectsUnparseablePrivateKey() {
        assertThrows(GeneralSecurityException.class,
                () -> BouncyCastleKEM.create("ML-KEM").decapsulate(new FakePrivateKey(new byte[] {1, 2, 3}), new byte[1088]));
    }

    @Test
    public void decapsulateRejectsPrivateKeyOfAnotherAlgorithm() throws Exception {
        final KeyPair rsa = SecurityUtils.getKeyPairGenerator("RSA").generateKeyPair();

        final GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
                () -> BouncyCastleKEM.create("ML-KEM").decapsulate(rsa.getPrivate(), new byte[1088]));

        assertTrue(e.getMessage().contains("Expected ML-KEM private key"), e.getMessage());
    }

    private static final class FakePublicKey implements PublicKey {
        private final byte[] encoded;

        FakePublicKey(final byte[] encoded) {
            this.encoded = encoded;
        }

        @Override
        public String getAlgorithm() {
            return "ML-KEM";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }
    }

    private static final class FakePrivateKey implements PrivateKey {
        private final byte[] encoded;

        FakePrivateKey(final byte[] encoded) {
            this.encoded = encoded;
        }

        @Override
        public String getAlgorithm() {
            return "ML-KEM";
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return encoded;
        }
    }
}
