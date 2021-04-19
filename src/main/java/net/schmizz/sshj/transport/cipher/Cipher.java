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

/** Wrapper for a cryptographic cipher, used either for encryption or decryption. */
public interface Cipher {

    enum Mode {
        Encrypt,
        Decrypt
    }

    /** @return the block size for this cipher */
    int getBlockSize();

    /** @return the size of the initialization vector */
    int getIVSize();

    /** @return Size of the authentication tag (AT) in bytes or 0 if this cipher does not support authentication */
    int getAuthenticationTagSize();

    /**
     * Initialize the cipher for encryption or decryption with the given private key and initialization vector
     *
     * @param mode whether this instance wil encrypt or decrypt
     * @param key  the key for the cipher
     * @param iv   initialization vector
     */
    void init(Mode mode, byte[] key, byte[] iv);

    /**
     * Performs in-place encryption or decryption on the given data.
     *
     * @param input       the subject
     * @param inputOffset offset at which to start
     * @param inputLen    number of bytes starting at {@code inputOffset}
     */
    void update(byte[] input, int inputOffset, int inputLen);

    /**
     * Adds the provided input data as additional authenticated data during encryption or decryption.
     *
     * @param  data      The additional data to authenticate
     * @param  offset    The offset of the additional data in the buffer
     * @param  length    The number of bytes in the buffer to use for authentication
     */
    void updateAAD(byte[] data, int offset, int length);

    /**
     * Adds the provided input data as additional authenticated data during encryption or decryption.
     *
     * @param  data      The data to authenticate
     */
    void updateAAD(byte[] data);

    /**
     * Performs in-place authenticated encryption or decryption with additional data (AEAD). Authentication tags are
     * implicitly appended after the output ciphertext or implicitly verified after the input ciphertext. Header data
     * indicated by the {@code aadLen} parameter are authenticated but not encrypted/decrypted, while payload data
     * indicated by the {@code inputLen} parameter are authenticated and encrypted/decrypted.
     *
     * @param  input     The input/output bytes
     * @param  offset    The offset of the data in the input buffer
     * @param  aadLen    The number of bytes to use as additional authenticated data - starting at offset
     * @param  inputLen  The number of bytes to update - starting at offset + aadLen
     */
    void updateWithAAD(byte[] input, int offset, int aadLen, int inputLen);

    void setSequenceNumber(long seq);
}
