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
package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.common.SshjKEM;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * Helper around the JCA implementation of ML-KEM-768 (FIPS&nbsp;203). Provides
 * client-side key generation and decapsulation, as well as server-side
 * encapsulation (used by the unit tests).
 *
 * <p>All cryptographic operations route through {@link SecurityUtils}: key generation
 * via {@link SecurityUtils#getKeyPairGenerator(String)}, encapsulation/decapsulation via
 * {@link SecurityUtils#getKEM(String)} (the JDK&nbsp;21+ {@code javax.crypto.KEM} API),
 * and public-key reconstruction from the SSH wire format via
 * {@link SecurityUtils#getKeyFactory(String)}. No dependency on Bouncy Castle classes
 * or any other specific provider remains here.</p>
 *
 * <p>For this parameter set, the byte sizes are:</p>
 * <ul>
 *   <li>Public key: {@value #PUBLIC_KEY_LENGTH} bytes</li>
 *   <li>Ciphertext: {@value #CIPHERTEXT_LENGTH} bytes</li>
 *   <li>Shared secret: {@value #SHARED_SECRET_LENGTH} bytes</li>
 * </ul>
 */
public final class MLKEM768 {

    /** Length in bytes of an ML-KEM-768 public key. */
    public static final int PUBLIC_KEY_LENGTH = 1184;

    /** Length in bytes of an ML-KEM-768 ciphertext. */
    public static final int CIPHERTEXT_LENGTH = 1088;

    /** Length in bytes of the shared secret produced by ML-KEM-768. */
    public static final int SHARED_SECRET_LENGTH = 32;

    /**
     * Algorithm name to pass to {@link SecurityUtils#getKeyPairGenerator(String)} and
     * {@link SecurityUtils#getKeyFactory(String)}. The JCA selects the parameter set from
     * this name.
     */
    static final String KEY_ALGORITHM = "ML-KEM-768";

    /**
     * Algorithm family name to pass to {@link SecurityUtils#getKEM(String)}. The JCA
     * {@code javax.crypto.KEM} provider only registers under the family name; the
     * parameter set is inferred from the {@link java.security.PublicKey} or
     * {@link java.security.PrivateKey} passed to {@code newEncapsulator} /
     * {@code newDecapsulator}.
     */
    static final String KEM_ALGORITHM = "ML-KEM";

    /**
     * Constant DER prefix for an X.509 {@code SubjectPublicKeyInfo} wrapping a 1184-byte
     * ML-KEM-768 public key. {@code AlgorithmIdentifier} OID is
     * {@code 2.16.840.1.101.3.4.4.2}; {@code BIT STRING} length is 1185 (raw key + the
     * leading "0 unused bits" byte).
     */
    private static final byte[] SPKI_PREFIX = new byte[] {
            (byte) 0x30, (byte) 0x82, (byte) 0x04, (byte) 0xb2,
            (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x09,
            (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
            (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x04,
            (byte) 0x02, (byte) 0x03, (byte) 0x82, (byte) 0x04,
            (byte) 0xa1, (byte) 0x00,
    };

    private KeyPair keyPair;

    /**
     * Generate an ephemeral ML-KEM-768 key pair via the JCA.
     *
     * @return the encoded public key (length {@value #PUBLIC_KEY_LENGTH}) in the raw
     *         wire format expected by the SSH hybrid KEX (the trailing portion of the
     *         SPKI encoding)
     * @throws GeneralSecurityException if no JCA provider supports ML-KEM-768 or the
     *         encoded public key is malformed
     */
    public byte[] generateKeyPair() throws GeneralSecurityException {
        keyPair = SecurityUtils.getKeyPairGenerator(KEY_ALGORITHM).generateKeyPair();
        final byte[] spki = keyPair.getPublic().getEncoded();
        if (spki.length != SPKI_PREFIX.length + PUBLIC_KEY_LENGTH) {
            throw new GeneralSecurityException(
                    "Unexpected ML-KEM-768 SPKI length " + spki.length
                            + " (expected " + (SPKI_PREFIX.length + PUBLIC_KEY_LENGTH) + ")");
        }
        final byte[] raw = new byte[PUBLIC_KEY_LENGTH];
        System.arraycopy(spki, SPKI_PREFIX.length, raw, 0, PUBLIC_KEY_LENGTH);
        return raw;
    }

    /**
     * Decapsulate a ciphertext received from the peer using the previously generated private key.
     *
     * @param ciphertext peer ciphertext (must be exactly {@value #CIPHERTEXT_LENGTH} bytes)
     * @return the shared secret (length {@value #SHARED_SECRET_LENGTH})
     * @throws GeneralSecurityException if the ciphertext has an invalid length or no key pair has been generated
     */
    public byte[] decapsulate(final byte[] ciphertext) throws GeneralSecurityException {
        if (keyPair == null) {
            throw new GeneralSecurityException("ML-KEM-768 key pair has not been generated");
        }
        if (ciphertext == null || ciphertext.length != CIPHERTEXT_LENGTH) {
            throw new GeneralSecurityException(
                    "ML-KEM-768 ciphertext length must be " + CIPHERTEXT_LENGTH + " bytes");
        }
        return SecurityUtils.getKEM(KEM_ALGORITHM).decapsulate(keyPair.getPrivate(), ciphertext);
    }

    /**
     * Server-side encapsulation against a peer public key. Used by the test suite to simulate
     * a server response without requiring an external SSH server.
     *
     * @param peerPublicKey peer public key (must be exactly {@value #PUBLIC_KEY_LENGTH} bytes)
     * @return the encapsulation result containing the ciphertext and the shared secret
     * @throws GeneralSecurityException if the peer public key has an invalid length or
     *         no JCA provider supports ML-KEM-768
     */
    public static SshjKEM.Encapsulated encapsulate(final byte[] peerPublicKey)
            throws GeneralSecurityException {
        if (peerPublicKey == null || peerPublicKey.length != PUBLIC_KEY_LENGTH) {
            throw new GeneralSecurityException(
                    "ML-KEM-768 public key length must be " + PUBLIC_KEY_LENGTH + " bytes");
        }
        final byte[] spki = new byte[SPKI_PREFIX.length + PUBLIC_KEY_LENGTH];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(peerPublicKey, 0, spki, SPKI_PREFIX.length, PUBLIC_KEY_LENGTH);
        final KeyFactory kf = SecurityUtils.getKeyFactory(KEY_ALGORITHM);
        final PublicKey reconstructed = kf.generatePublic(new X509EncodedKeySpec(spki));
        return SecurityUtils.getKEM(KEM_ALGORITHM).encapsulate(reconstructed);
    }
}
