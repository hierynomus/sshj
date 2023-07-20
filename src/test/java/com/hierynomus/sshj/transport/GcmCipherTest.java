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

import com.hierynomus.sshj.transport.cipher.GcmCiphers;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.transport.cipher.Cipher;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class GcmCipherTest {

    public static GcmCiphers.Factory[] cipherFactories() {
        return new GcmCiphers.Factory[] { GcmCiphers.AES128GCM(), GcmCiphers.AES256GCM() }; };

    @ParameterizedTest
    @MethodSource("cipherFactories")
    public void testEncryptDecrypt(GcmCiphers.Factory factory) throws Exception {
        Cipher enc = factory.create();
        byte[] key = new byte[enc.getBlockSize()];
        byte[] iv = new byte[enc.getIVSize()];
        enc.init(Cipher.Mode.Encrypt, key, iv);

        byte[] aad = getClass().getName().getBytes(StandardCharsets.UTF_8);
        enc.updateAAD(aad);
        String plaintext = "[Secret authenticated message using AES-GCM";
        byte[] ptBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[ptBytes.length + enc.getAuthenticationTagSize()];
        System.arraycopy(ptBytes, 0, output, 0, ptBytes.length);
        enc.update(output, 0, ptBytes.length);

        Cipher dec = factory.create();
        dec.init(Cipher.Mode.Decrypt, key, iv);
        dec.updateAAD(aad);
        byte[] input = output.clone();
        dec.update(input, 0, ptBytes.length);
        assertEquals(getClass().getName(), new String(aad, StandardCharsets.UTF_8));
        assertEquals(plaintext, new String(input, 0, ptBytes.length, StandardCharsets.UTF_8));

        byte[] corrupted = output.clone();
        corrupted[corrupted.length - 1] += 1;
        Cipher failingDec = factory.create();
        failingDec.init(Cipher.Mode.Decrypt, key, iv);
        try {
            failingDec.updateAAD(aad.clone());
            failingDec.update(corrupted, 0, ptBytes.length);
            fail("Modified authentication tag should not validate");
        } catch (SSHRuntimeException e) {
            assertNotNull(e);
            assertEquals(AEADBadTagException.class, e.getCause().getClass());
        }
    }
}
