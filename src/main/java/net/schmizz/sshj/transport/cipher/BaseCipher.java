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
package net.schmizz.sshj.transport.cipher;

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/** Base class for all Cipher implementations delegating to the JCE provider. */
public abstract class BaseCipher
        implements Cipher {

    private static byte[] resize(byte[] data, int size) {
        if (data.length > size) {
            final byte[] tmp = new byte[size];
            System.arraycopy(data, 0, tmp, 0, size);
            data = tmp;
        }
        return data;
    }

    private final int ivsize;
    private final int bsize;
    private final String algorithm;
    private final String transformation;

    private javax.crypto.Cipher cipher;

    public BaseCipher(int ivsize, int bsize, String algorithm, String transformation) {
        this.ivsize = ivsize;
        this.bsize = bsize;
        this.algorithm = algorithm;
        this.transformation = transformation;
    }

    @Override
    public int getBlockSize() {
        return bsize;
    }

    @Override
    public int getIVSize() {
        return ivsize;
    }

    @Override
    public void init(Mode mode, byte[] key, byte[] iv) {
        key = BaseCipher.resize(key, bsize);
        iv = BaseCipher.resize(iv, ivsize);
        try {
            cipher = SecurityUtils.getCipher(transformation);
            initCipher(cipher, mode, key, iv);
        } catch (GeneralSecurityException e) {
            cipher = null;
            throw new SSHRuntimeException(e);
        }
    }

    protected abstract void initCipher(javax.crypto.Cipher cipher, Mode mode, byte[] key, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException;
    protected SecretKeySpec getKeySpec(byte[] key) {
        return new SecretKeySpec(key, algorithm);
    }

    protected int getMode(Mode mode) {
        return mode == Mode.Encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE;
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) {
        try {
            cipher.update(input, inputOffset, inputLen, input, inputOffset);
        } catch (ShortBufferException e) {
            throw new SSHRuntimeException(e);
        }
    }

}
