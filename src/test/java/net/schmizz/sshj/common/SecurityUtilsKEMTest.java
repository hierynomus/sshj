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

import com.hierynomus.sshj.test.MLKEM;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the KEM related entry points of {@link SecurityUtils}, which select between the JDK
 * {@code javax.crypto.KEM} API and the Bouncy Castle fallback depending on the runtime.
 */
public class SecurityUtilsKEMTest {

    @Test
    @DisabledIf(value = MLKEM.UNSUPPORTED, disabledReason = MLKEM.REASON)
    public void getKEMReturnsWorkingImplementation() throws Exception {
        final KeyPair keyPair = SecurityUtils.getKeyPairGenerator("ML-KEM-768").generateKeyPair();
        final SshjKEM kem = SecurityUtils.getKEM("ML-KEM");

        final SshjKEM.Encapsulated encapsulated = kem.encapsulate(keyPair.getPublic());
        final byte[] decapsulated = kem.decapsulate(keyPair.getPrivate(), encapsulated.getCiphertext());

        assertArrayEquals(encapsulated.getSharedSecret(), decapsulated);
    }

    @Test
    public void getKEMRejectsUnknownAlgorithm() {
        assertThrows(NoSuchAlgorithmException.class, () -> SecurityUtils.getKEM("NO-SUCH-KEM"));
    }

    @Test
    public void reportsAvailableJcaService() {
        assertTrue(SecurityUtils.isAlgorithmAvailable("MessageDigest", "SHA-256"));
    }

    @Test
    public void reportsMissingJcaService() {
        assertFalse(SecurityUtils.isAlgorithmAvailable("KeyPairGenerator", "NO-SUCH-ALGORITHM"));
    }

    @Test
    public void kemAvailabilityIsConsistentWithGetKEM() {
        final boolean available = SecurityUtils.isAlgorithmAvailable("KEM", "ML-KEM");
        boolean obtained;
        try {
            obtained = SecurityUtils.getKEM("ML-KEM") != null;
        } catch (GeneralSecurityException e) {
            obtained = false;
        }
        assertEquals(available, obtained,
                "isAlgorithmAvailable(KEM) should agree with whether getKEM can supply one");
    }

    @Test
    public void onlyConsultsTheConfiguredProviderWhenOneIsSet() {
        final String original = SecurityUtils.getSecurityProvider();
        try {
            // A provider that is not installed offers nothing at all.
            SecurityUtils.setSecurityProvider("NoSuchProvider");
            assertFalse(SecurityUtils.isAlgorithmAvailable("MessageDigest", "SHA-256"));
            assertNotNull(SecurityUtils.getSecurityProvider());
        } finally {
            SecurityUtils.setSecurityProvider(original);
        }
        assertTrue(SecurityUtils.isAlgorithmAvailable("MessageDigest", "SHA-256"));
    }
}
