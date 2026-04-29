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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Helper around the Bouncy Castle lightweight implementation of ML-KEM-768
 * (FIPS 203). Provides client-side key generation and decapsulation, as well
 * as server-side encapsulation (used by the unit tests).
 *
 * <p>For the parameter set used here, the byte sizes are:</p>
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

    private MLKEMPublicKeyParameters publicKey;
    private MLKEMPrivateKeyParameters privateKey;

    /**
     * Generate an ephemeral ML-KEM-768 key pair using the provided source of randomness.
     *
     * @param random source of randomness
     * @return the encoded public key (length {@value #PUBLIC_KEY_LENGTH})
     */
    public byte[] generateKeyPair(final SecureRandom random) {
        final MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        generator.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
        final AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        publicKey = (MLKEMPublicKeyParameters) keyPair.getPublic();
        privateKey = (MLKEMPrivateKeyParameters) keyPair.getPrivate();
        return publicKey.getEncoded();
    }

    /**
     * Decapsulate a ciphertext received from the peer using the previously generated private key.
     *
     * @param ciphertext peer ciphertext (must be exactly {@value #CIPHERTEXT_LENGTH} bytes)
     * @return the shared secret (length {@value #SHARED_SECRET_LENGTH})
     * @throws GeneralSecurityException if the ciphertext has an invalid length or no key pair has been generated
     */
    public byte[] decapsulate(final byte[] ciphertext) throws GeneralSecurityException {
        if (privateKey == null) {
            throw new GeneralSecurityException("ML-KEM-768 key pair has not been generated");
        }
        if (ciphertext == null || ciphertext.length != CIPHERTEXT_LENGTH) {
            throw new GeneralSecurityException(
                    "ML-KEM-768 ciphertext length must be " + CIPHERTEXT_LENGTH + " bytes");
        }
        return new MLKEMExtractor(privateKey).extractSecret(ciphertext);
    }

    /**
     * Server-side encapsulation against a peer public key. Used by the test suite to simulate
     * a server response without requiring an external SSH server.
     *
     * @param peerPublicKey peer public key (must be exactly {@value #PUBLIC_KEY_LENGTH} bytes)
     * @param random source of randomness
     * @return the encapsulation result containing the ciphertext and the shared secret
     * @throws GeneralSecurityException if the peer public key has an invalid length
     */
    public static SecretWithEncapsulation encapsulate(final byte[] peerPublicKey, final SecureRandom random)
            throws GeneralSecurityException {
        if (peerPublicKey == null || peerPublicKey.length != PUBLIC_KEY_LENGTH) {
            throw new GeneralSecurityException(
                    "ML-KEM-768 public key length must be " + PUBLIC_KEY_LENGTH + " bytes");
        }
        final MLKEMPublicKeyParameters peer = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, peerPublicKey);
        return new MLKEMGenerator(random).generateEncapsulated(peer);
    }
}
