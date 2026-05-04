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

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MLKEM768Test {

    @Test
    public void generateKeyPairProducesCorrectlySizedPublicKey() throws GeneralSecurityException {
        final MLKEM768 mlkem = new MLKEM768();
        final byte[] publicKey = mlkem.generateKeyPair();

        assertNotNull(publicKey);
        assertEquals(MLKEM768.PUBLIC_KEY_LENGTH, publicKey.length);
    }

    @Test
    public void encapsulateAndDecapsulateProduceMatchingSecret() throws GeneralSecurityException {
        final SecureRandom random = new SecureRandom();
        final MLKEM768 mlkem = new MLKEM768();

        final byte[] publicKey = mlkem.generateKeyPair();
        final SecretWithEncapsulation server = MLKEM768.encapsulate(publicKey, random);

        assertEquals(MLKEM768.CIPHERTEXT_LENGTH, server.getEncapsulation().length);
        assertEquals(MLKEM768.SHARED_SECRET_LENGTH, server.getSecret().length);

        final byte[] clientSecret = mlkem.decapsulate(server.getEncapsulation());

        assertEquals(MLKEM768.SHARED_SECRET_LENGTH, clientSecret.length);
        assertArrayEquals(server.getSecret(), clientSecret);
    }

    @Test
    public void decapsulateRejectsCiphertextOfWrongLength() throws GeneralSecurityException {
        final MLKEM768 mlkem = new MLKEM768();
        mlkem.generateKeyPair();

        assertThrows(GeneralSecurityException.class, () -> mlkem.decapsulate(new byte[10]));
    }

    @Test
    public void decapsulateBeforeKeyGenFails() {
        assertThrows(GeneralSecurityException.class,
                () -> new MLKEM768().decapsulate(new byte[MLKEM768.CIPHERTEXT_LENGTH]));
    }

    @Test
    public void encapsulateRejectsPublicKeyOfWrongLength() {
        assertThrows(GeneralSecurityException.class,
                () -> MLKEM768.encapsulate(new byte[10], new SecureRandom()));
    }
}
