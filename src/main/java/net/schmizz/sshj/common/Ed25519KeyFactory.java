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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Factory for generating Edwards-curve 25519 Public and Private Keys
 */
public class Ed25519KeyFactory {
    private static final int KEY_LENGTH = 32;

    private static final String KEY_ALGORITHM = "Ed25519";

    private static final byte[] ED25519_PKCS8_PRIVATE_KEY_HEADER = Base64.getDecoder().decode("MC4CAQEwBQYDK2VwBCIEIA");

    private static final byte[] ED25519_PKCS8_PUBLIC_KEY_HEADER = Base64.getDecoder().decode("MCowBQYDK2VwAyEA");

    private static final int PRIVATE_KEY_ENCODED_LENGTH = 48;

    private static final int PUBLIC_KEY_ENCODED_LENGTH = 44;

    private Ed25519KeyFactory() {

    }

    /**
     * Get Edwards-curve Private Key for private key binary
     *
     * @param privateKeyBinary Private Key byte array consisting of 32 bytes
     * @return Edwards-curve 25519 Private Key
     * @throws GeneralSecurityException Thrown on failure to generate Private Key
     */
    public static PrivateKey getPrivateKey(final byte[] privateKeyBinary) throws GeneralSecurityException {
        Objects.requireNonNull(privateKeyBinary, "Private Key byte array required");
        if (privateKeyBinary.length == KEY_LENGTH) {
            final byte[] privateKeyEncoded = new byte[PRIVATE_KEY_ENCODED_LENGTH];
            System.arraycopy(ED25519_PKCS8_PRIVATE_KEY_HEADER, 0, privateKeyEncoded, 0, ED25519_PKCS8_PRIVATE_KEY_HEADER.length);
            System.arraycopy(privateKeyBinary, 0, privateKeyEncoded, ED25519_PKCS8_PRIVATE_KEY_HEADER.length, KEY_LENGTH);
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);

            final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KEY_ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } else {
            throw new IllegalArgumentException("Key length of 32 bytes required");
        }
    }

    /**
     * Get Edwards-curve Public Key for public key binary
     *
     * @param publicKeyBinary Public Key byte array consisting of 32 bytes
     * @return Edwards-curve 25519 Public Key
     * @throws GeneralSecurityException Thrown on failure to generate Public Key
     */
    public static PublicKey getPublicKey(final byte[] publicKeyBinary) throws GeneralSecurityException {
        Objects.requireNonNull(publicKeyBinary, "Public Key byte array required");
        if (publicKeyBinary.length == KEY_LENGTH) {
            final byte[] publicKeyEncoded = new byte[PUBLIC_KEY_ENCODED_LENGTH];
            System.arraycopy(ED25519_PKCS8_PUBLIC_KEY_HEADER, 0, publicKeyEncoded, 0, ED25519_PKCS8_PUBLIC_KEY_HEADER.length);
            System.arraycopy(publicKeyBinary, 0, publicKeyEncoded, ED25519_PKCS8_PUBLIC_KEY_HEADER.length, KEY_LENGTH);
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyEncoded);

            final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KEY_ALGORITHM);
            return keyFactory.generatePublic(keySpec);
        } else {
            throw new IllegalArgumentException("Key length of 32 bytes required");
        }
    }
}
