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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Exercises {@link JcaKEM} directly. {@code JcaKEM} accesses the JDK&nbsp;21+
 * {@code javax.crypto.KEM} API via reflection, so we want to verify that:
 *
 * <ul>
 *   <li>{@link JcaKEM#isApiAvailable()} agrees with the actual presence of the API
 *       class on the runtime,</li>
 *   <li>a successful {@code create(...)} produces an instance that can round-trip
 *       encap/decap to a matching shared secret,</li>
 *   <li>the reflective exception-unwrapping paths translate
 *       {@code InvocationTargetException} into the expected
 *       {@link NoSuchAlgorithmException} / {@link NoSuchProviderException} /
 *       {@link GeneralSecurityException} types instead of leaking the reflective
 *       wrapper.</li>
 * </ul>
 *
 * <p>All tests are gated on {@link JcaKEM#isApiAvailable()} so they skip cleanly
 * on Java&nbsp;&lt;&nbsp;21 (the existing {@code BouncyCastleKEMTest} covers the
 * fallback path on older runtimes).</p>
 */
public class JcaKEMTest {

    @BeforeAll
    public static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void apiAvailabilityMatchesClassPresence() {
        boolean classPresent;
        try {
            Class.forName("javax.crypto.KEM");
            classPresent = true;
        } catch (ClassNotFoundException e) {
            classPresent = false;
        }
        assertEquals(classPresent, JcaKEM.isApiAvailable(),
                "JcaKEM.isApiAvailable() must reflect actual javax.crypto.KEM presence");
    }

    @Test
    public void roundTripProducesMatchingSecretWithDefaultProvider() throws Exception {
        assumeTrue(JcaKEM.isApiAvailable(), "javax.crypto.KEM not available on this JRE");
        assumeTrue(providerOffersService("KEM", "ML-KEM"),
                "No JCA provider registers the ML-KEM KEM service on this JRE");

        KeyPair kp = generateMlKem768KeyPair();
        SshjKEM kem = JcaKEM.create("ML-KEM", null);

        SshjKEM.Encapsulated encapsulated = kem.encapsulate(kp.getPublic());
        assertNotNull(encapsulated);
        assertEquals(1088, encapsulated.getCiphertext().length, "ML-KEM-768 ciphertext length");
        assertEquals(32, encapsulated.getSharedSecret().length, "ML-KEM-768 shared secret length");

        byte[] decapsulated = kem.decapsulate(kp.getPrivate(), encapsulated.getCiphertext());
        assertArrayEquals(encapsulated.getSharedSecret(), decapsulated,
                "decapsulated secret must equal encapsulated secret");
    }

    @Test
    public void roundTripProducesMatchingSecretWithExplicitProvider() throws Exception {
        assumeTrue(JcaKEM.isApiAvailable(), "javax.crypto.KEM not available on this JRE");
        assumeTrue(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getService("KEM", "ML-KEM") != null,
                "BouncyCastle does not register ML-KEM KEM service on this JRE");

        KeyPair kp = generateMlKem768KeyPair();
        SshjKEM kem = JcaKEM.create("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);

        SshjKEM.Encapsulated encapsulated = kem.encapsulate(kp.getPublic());
        byte[] decapsulated = kem.decapsulate(kp.getPrivate(), encapsulated.getCiphertext());
        assertArrayEquals(encapsulated.getSharedSecret(), decapsulated);
    }

    @Test
    public void createUnwrapsNoSuchAlgorithmException() {
        assumeTrue(JcaKEM.isApiAvailable(), "javax.crypto.KEM not available on this JRE");

        NoSuchAlgorithmException ex = assertThrows(NoSuchAlgorithmException.class,
                () -> JcaKEM.create("BOGUS-KEM-ALGORITHM", null));
        // Must be a direct NSAE, not a reflective wrapper like
        // InvocationTargetException or some generic GeneralSecurityException.
        assertEquals(NoSuchAlgorithmException.class, ex.getClass(),
                "exception type must be exactly NoSuchAlgorithmException");
    }

    @Test
    public void createUnwrapsNoSuchProviderException() {
        assumeTrue(JcaKEM.isApiAvailable(), "javax.crypto.KEM not available on this JRE");

        NoSuchProviderException ex = assertThrows(NoSuchProviderException.class,
                () -> JcaKEM.create("ML-KEM", "ThisProviderDoesNotExist"));
        assertEquals(NoSuchProviderException.class, ex.getClass(),
                "exception type must be exactly NoSuchProviderException");
    }

    @Test
    public void decapsulateRejectsWrongLengthCiphertext() throws Exception {
        assumeTrue(JcaKEM.isApiAvailable(), "javax.crypto.KEM not available on this JRE");
        assumeTrue(providerOffersService("KEM", "ML-KEM"),
                "No JCA provider registers the ML-KEM KEM service on this JRE");

        KeyPair kp = generateMlKem768KeyPair();
        SshjKEM kem = JcaKEM.create("ML-KEM", null);

        byte[] tooShort = new byte[10];
        GeneralSecurityException ex = assertThrows(GeneralSecurityException.class,
                () -> kem.decapsulate(kp.getPrivate(), tooShort));
        // The reflective layer must translate any thrown checked exception into
        // a GeneralSecurityException (or subclass), never let an
        // InvocationTargetException or RuntimeException leak.
        assertNotNull(ex.getMessage() != null ? ex.getMessage() : ex.getCause(),
                "exception should carry a message or cause");
    }

    private static KeyPair generateMlKem768KeyPair() throws Exception {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("ML-KEM-768");
        } catch (NoSuchAlgorithmException firstTry) {
            // SunJCE on JDK 21 doesn't register ML-KEM-768; explicitly fall back to BC.
            kpg = KeyPairGenerator.getInstance("ML-KEM-768", BouncyCastleProvider.PROVIDER_NAME);
        }
        return kpg.generateKeyPair();
    }

    private static boolean providerOffersService(String type, String algorithm) {
        for (java.security.Provider p : Security.getProviders()) {
            if (p.getService(type, algorithm) != null) {
                return true;
            }
        }
        return false;
    }
}
