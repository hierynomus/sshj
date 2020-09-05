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
package com.hierynomus.sshj.transport.cipher;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.transport.cipher.BaseCipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

public class GcmCipher extends BaseCipher {

    protected Mode mode;
    protected boolean initialized;
    protected CounterGCMParameterSpec parameters;
    protected SecretKey secretKey;

    public GcmCipher(int ivsize, int authSize, int bsize, String algorithm, String transformation) {
        super(ivsize, authSize, bsize, algorithm, transformation);
    }

    protected Cipher getInitializedCipherInstance() throws GeneralSecurityException {
        Cipher cipher = getCipherInstance();
        if (!initialized) {
            cipher.init(mode == Mode.Encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, parameters);
            initialized = true;
        }
        return cipher;
    }

    @Override
    protected void initCipher(Cipher cipher, Mode mode, byte[] key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.mode = mode;
        this.secretKey = getKeySpec(key);
        this.parameters = new CounterGCMParameterSpec(getAuthenticationTagSize() * Byte.SIZE, iv);
        cipher.init(getMode(mode), secretKey, parameters);
        initialized = true;
    }

    @Override
    public void updateAAD(byte[] data, int offset, int length) {
        try {
            Cipher cipher = getInitializedCipherInstance();
            cipher.updateAAD(data, offset, length);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException("Error updating data through cipher", e);
        }
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) {
        if (mode == Mode.Decrypt) {
            inputLen += getAuthenticationTagSize();
        }
        try {
            Cipher cipher = getInitializedCipherInstance();
            cipher.doFinal(input, inputOffset, inputLen, input, inputOffset);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException("Error updating data through cipher", e);
        }
        parameters.incrementCounter();
        initialized = false;
    }

    /**
     * Algorithm parameters for AES/GCM that assumes the IV uses an 8-byte counter field as its most significant bytes.
     */
    protected static class CounterGCMParameterSpec extends GCMParameterSpec {
        protected final byte[] iv;

        protected CounterGCMParameterSpec(int tLen, byte[] src) {
            super(tLen, src);
            if (src.length != 12) {
                throw new IllegalArgumentException("GCM nonce must be 12 bytes, but given len=" + src.length);
            }
            iv = src.clone();
        }

        protected void incrementCounter() {
            int off = iv.length - 8;
            long counter = Buffer.getLong(iv, off, 8);
            Buffer.putLong(addExact(counter, 1L), iv, off, 8);
        }

        @Override
        public byte[] getIV() {
            // JCE implementation of GCM will complain if the reference doesn't change between inits
            return iv.clone();
        }

        static long addExact(long var0, long var2) {
            long var4 = var0 + var2;
            if (((var0 ^ var4) & (var2 ^ var4)) < 0L) {
                throw new ArithmeticException("long overflow");
            } else {
                return var4;
            }
        }
    }
}
