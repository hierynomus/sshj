/*
 * Copyright 2010-2012 sshj contributors
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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
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

}
