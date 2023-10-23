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

import java.security.GeneralSecurityException;

import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.spec.IvParameterSpec;

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.cipher.BaseCipher;

public class ChachaPolyCipher extends BaseCipher {

    private static final int CHACHA_KEY_SIZE = 32;
    private static final int AAD_LENGTH = 4;
    private static final int POLY_TAG_LENGTH = 16;

    private static final String CIPHER_CHACHA = "CHACHA";
    private static final String MAC_POLY1305 = "POLY1305";

    private static final byte[] POLY_KEY_INPUT = new byte[32];

    private final int authSize;

    private byte[] encryptedAad;

    protected Mode mode;
    protected javax.crypto.Cipher aadCipher;
    protected javax.crypto.Mac mac;
    protected java.security.Key cipherKey;
    protected java.security.Key aadCipherKey;

    public ChachaPolyCipher(int authSize, int bsize, String algorithm) {
        super(0, bsize, algorithm, CIPHER_CHACHA);
        this.authSize = authSize;
    }

    @Override
    public int getAuthenticationTagSize() {
        return authSize;
    }

    @Override
    public void setSequenceNumber(long seq) {
        byte[] seqAsBytes = longToBytes(seq);
        AlgorithmParameterSpec ivSpec = new IvParameterSpec(seqAsBytes);

        try {
            cipher.init(getMode(mode), cipherKey, ivSpec);
            aadCipher.init(getMode(mode), aadCipherKey, ivSpec);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }

        byte[] polyKeyBytes = cipher.update(POLY_KEY_INPUT);
        cipher.update(POLY_KEY_INPUT); // this update is required to set the block counter of ChaCha to 1
        try {
            mac.init(getKeySpec(polyKeyBytes));
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }

        encryptedAad = null;
    }

    @Override
    protected void initCipher(javax.crypto.Cipher cipher, Mode mode, byte[] key, byte[] iv) {
        this.mode = mode;

        cipherKey = getKeySpec(Arrays.copyOfRange(key, 0, CHACHA_KEY_SIZE));
        aadCipherKey = getKeySpec(Arrays.copyOfRange(key, CHACHA_KEY_SIZE, 2 * CHACHA_KEY_SIZE));

        try {
            aadCipher = SecurityUtils.getCipher(CIPHER_CHACHA);
            mac = SecurityUtils.getMAC(MAC_POLY1305);
        } catch (GeneralSecurityException e) {
            cipher = null;
            aadCipher = null;
            mac = null;
            throw new SSHRuntimeException(e);
        }

        setSequenceNumber(0);
    }

    @Override
    public void updateAAD(byte[] data, int offset, int length) {
        if (offset != 0 || length != AAD_LENGTH) {
            throw new IllegalArgumentException(
                    String.format("updateAAD called with offset %d and length %d", offset, length));
        }

        if (mode == Mode.Decrypt) {
            encryptedAad = Arrays.copyOfRange(data, 0, AAD_LENGTH);
        }

        try {
            aadCipher.update(data, 0, AAD_LENGTH, data, 0);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException("Error updating data through cipher", e);
        }
    }

    @Override
    public void updateAAD(byte[] data) {
        updateAAD(data, 0, AAD_LENGTH);
    }

    @Override
    public void update(byte[] input, int inputOffset, int inputLen) {
        if (inputOffset != 0 && inputOffset != AAD_LENGTH) {
            throw new IllegalArgumentException("updateAAD called with inputOffset " + inputOffset);
        }

        final int macInputLength = inputOffset + inputLen;
        if (mode == Mode.Decrypt) {
            final byte[] macInput = new byte[macInputLength];

            if (inputOffset == 0) {
                // Handle decryption without AAD
                System.arraycopy(input, 0, macInput, 0, inputLen);
            } else {
                // Handle decryption with previous AAD from updateAAD()
                System.arraycopy(encryptedAad, 0, macInput, 0, AAD_LENGTH);
                System.arraycopy(input, AAD_LENGTH, macInput, AAD_LENGTH, inputLen);
            }

            final byte[] expectedPolyTag = mac.doFinal(macInput);
            final byte[] actualPolyTag = Arrays.copyOfRange(input, macInputLength, macInputLength + POLY_TAG_LENGTH);
            if (!MessageDigest.isEqual(actualPolyTag, expectedPolyTag)) {
                throw new SSHRuntimeException("MAC Error");
            }
        }

        try {
            cipher.update(input, inputOffset, inputLen, input, inputOffset);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException("ChaCha20 cipher processing failed", e);
        }

        if (mode == Mode.Encrypt) {
            byte[] macInput = Arrays.copyOf(input, macInputLength);
            byte[] polyTag = mac.doFinal(macInput);
            System.arraycopy(polyTag, 0, input, macInputLength, POLY_TAG_LENGTH);
        }
    }

    private byte[] longToBytes(long lng) {
        return new byte[] { (byte) (lng >> 56), (byte) (lng >> 48), (byte) (lng >> 40), (byte) (lng >> 32),
                (byte) (lng >> 24), (byte) (lng >> 16), (byte) (lng >> 8), (byte) lng };
    }
}
