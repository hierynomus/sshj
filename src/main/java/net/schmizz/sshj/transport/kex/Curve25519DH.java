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

import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.random.Random;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Key Exchange Method using Curve25519 as defined in RFC 8731
 */
public class Curve25519DH extends DHBase {

    private static final String ALGORITHM = "X25519";

    private static final int ENCODED_ALGORITHM_ID_KEY_LENGTH = 44;

    private static final int ALGORITHM_ID_LENGTH = 12;

    private static final int KEY_LENGTH = 32;

    private final byte[] algorithmId = new byte[ALGORITHM_ID_LENGTH];

    public Curve25519DH() {
        super(ALGORITHM, ALGORITHM);
    }

    /**
     * Compute Shared Secret Key using Diffie-Hellman Curve25519 known as X25519
     *
     * @param peerPublicKey Peer public key bytes
     * @throws GeneralSecurityException Thrown on key agreement failures
     */
    @Override
    void computeK(final byte[] peerPublicKey) throws GeneralSecurityException {
        final KeyFactory keyFactory = SecurityUtils.getKeyFactory(ALGORITHM);
        final KeySpec peerPublicKeySpec = getPeerPublicKeySpec(peerPublicKey);
        final PublicKey generatedPeerPublicKey = keyFactory.generatePublic(peerPublicKeySpec);

        agreement.doPhase(generatedPeerPublicKey, true);
        final byte[] sharedSecretKey = agreement.generateSecret();
        final BigInteger sharedSecretNumber = new BigInteger(BigInteger.ONE.signum(), sharedSecretKey);
        setK(sharedSecretNumber);
    }

    /**
     * Initialize Key Agreement with generated Public and Private Key Pair
     *
     * @param params Parameters not used
     * @param randomFactory Random Factory not used
     * @throws GeneralSecurityException Thrown on key agreement initialization failures
     */
    @Override
    public void init(final AlgorithmParameterSpec params, final Factory<Random> randomFactory) throws GeneralSecurityException {
        final KeyPair keyPair = generator.generateKeyPair();
        agreement.init(keyPair.getPrivate());
        setPublicKey(keyPair.getPublic());
    }

    private void setPublicKey(final PublicKey publicKey) {
        final byte[] encoded = publicKey.getEncoded();

        // Encoded public key consists of the algorithm identifier and public key
        if (encoded.length == ENCODED_ALGORITHM_ID_KEY_LENGTH) {
            final byte[] publicKeyEncoded = new byte[KEY_LENGTH];
            System.arraycopy(encoded, ALGORITHM_ID_LENGTH, publicKeyEncoded, 0, KEY_LENGTH);
            setE(publicKeyEncoded);

            // Save Algorithm Identifier byte array
            System.arraycopy(encoded, 0, algorithmId, 0, ALGORITHM_ID_LENGTH);
        } else {
            throw new IllegalArgumentException(String.format("X25519 unsupported public key length [%d]", encoded.length));
        }
    }

    private KeySpec getPeerPublicKeySpec(final byte[] peerPublicKey) {
        final byte[] encodedKeySpec = new byte[ENCODED_ALGORITHM_ID_KEY_LENGTH];
        System.arraycopy(algorithmId, 0, encodedKeySpec, 0, ALGORITHM_ID_LENGTH);
        System.arraycopy(peerPublicKey, 0, encodedKeySpec, ALGORITHM_ID_LENGTH, KEY_LENGTH);
        return new X509EncodedKeySpec(encodedKeySpec);
    }
}
