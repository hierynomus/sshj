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
package net.schmizz.sshj.userauth.keyprovider;

import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.userauth.password.PasswordUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Objects;

/**
 * PuTTY Key Derivation Function supporting Version 1 and 2 Key files with historical SHA-1 key derivation
 */
class V1PuTTYSecretKeyDerivationFunction implements PuTTYSecretKeyDerivationFunction {
    private static final String SECRET_KEY_ALGORITHM = "AES";

    private static final String DIGEST_ALGORITHM = "SHA-1";

    /**
     * Derive Secret Key from provided passphrase characters
     *
     * @param passphrase Passphrase characters required
     * @return Derived Secret Key
     */
    public SecretKey deriveSecretKey(char[] passphrase) {
        Objects.requireNonNull(passphrase, "Passphrase required");

        final MessageDigest digest = getMessageDigest();
        final byte[] encodedPassphrase = PasswordUtils.toByteArray(passphrase);

        // Sequence number 0
        digest.update(new byte[]{0, 0, 0, 0});
        digest.update(encodedPassphrase);
        final byte[] key1 = digest.digest();

        // Sequence number 1
        digest.update(new byte[]{0, 0, 0, 1});
        digest.update(encodedPassphrase);
        final byte[] key2 = digest.digest();

        Arrays.fill(encodedPassphrase, (byte) 0);

        final byte[] secretKeyEncoded = new byte[32];
        System.arraycopy(key1, 0, secretKeyEncoded, 0, 20);
        System.arraycopy(key2, 0, secretKeyEncoded, 20, 12);

        return new SecretKeySpec(secretKeyEncoded, SECRET_KEY_ALGORITHM);
    }

    private MessageDigest getMessageDigest() {
        try {
            return SecurityUtils.getMessageDigest(DIGEST_ALGORITHM);
        } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
            final String message = String.format("Message Digest Algorithm [%s] not supported", DIGEST_ALGORITHM);
            throw new IllegalStateException(message, e);
        }
    }
}
