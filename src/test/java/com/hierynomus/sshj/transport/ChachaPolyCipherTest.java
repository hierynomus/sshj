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
package com.hierynomus.sshj.transport;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.hierynomus.sshj.transport.cipher.ChachaPolyCiphers;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.transport.cipher.Cipher;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class ChachaPolyCipherTest {

    private static final int AAD_LENGTH = 4;
    private static final int POLY_TAG_LENGTH = 16;

    private static final ChachaPolyCiphers.Factory FACTORY = ChachaPolyCiphers.CHACHA_POLY_OPENSSH();
    private static final String PLAINTEXT = "[Secret authenticated message using Chacha20Poly1305";

    @Test
    public void testEncryptDecrypt() {
        Cipher enc = FACTORY.create();
        byte[] key = new byte[enc.getBlockSize()];
        Arrays.fill(key, (byte) 1);
        enc.init(Cipher.Mode.Encrypt, key, new byte[0]);

        byte[] aad = new byte[AAD_LENGTH];
        byte[] ptBytes = PLAINTEXT.getBytes(StandardCharsets.UTF_8);
        byte[] message = new byte[AAD_LENGTH + ptBytes.length + POLY_TAG_LENGTH];
        Arrays.fill(aad, (byte) 2);
        System.arraycopy(aad, 0, message, 0, AAD_LENGTH);
        System.arraycopy(ptBytes, 0, message, AAD_LENGTH, ptBytes.length);

        enc.updateWithAAD(message, 0, AAD_LENGTH, ptBytes.length);
        byte[] corrupted = message.clone();

        Cipher dec = FACTORY.create();
        dec.init(Cipher.Mode.Decrypt, key, new byte[0]);
        dec.updateWithAAD(message, 0, AAD_LENGTH, ptBytes.length);

        assertArrayEquals(aad, Arrays.copyOf(message, AAD_LENGTH));
        String decodedString =
            new String(Arrays.copyOfRange(message, AAD_LENGTH, AAD_LENGTH + ptBytes.length), StandardCharsets.UTF_8);
        assertEquals(PLAINTEXT, decodedString);

        corrupted[corrupted.length - 1] += 1;
        Cipher failingDec = FACTORY.create();
        failingDec.init(Cipher.Mode.Decrypt, key, new byte[0]);
        try {
            failingDec.updateWithAAD(corrupted, 0, AAD_LENGTH, ptBytes.length);
            fail("Modified authentication tag should not validate");
        } catch (SSHRuntimeException e) {
            assertEquals("MAC Error", e.getMessage());
        }
    }

    @Test
    public void testCheckOnUpdateParameters() {
        Cipher cipher = FACTORY.create();
        try {
            cipher.update(null, 8, 42);
            fail("Invalid inputOffset should trigger exception");
        } catch (IllegalArgumentException e) {
            assertEquals("updateAAD called with inputOffset 8", e.getMessage());
        }
    }

    @Test
    public void testCheckOnUpdateAADParameters() {
        Cipher cipher = FACTORY.create();
        try {
            cipher.updateAAD(null, 1, AAD_LENGTH);
            fail("Invalid offset should trigger exception");
        } catch (IllegalArgumentException e) {
            assertEquals("updateAAD called with offset 1 and length 4", e.getMessage());
        }

        try {
            cipher.updateAAD(null, 0, 5);
            fail("Invalid length should trigger exception");
        } catch (IllegalArgumentException e) {
            assertEquals("updateAAD called with offset 0 and length 5", e.getMessage());
        }
    }
}
