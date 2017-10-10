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

import net.schmizz.sshj.transport.cipher.BlockCipher;
import net.schmizz.sshj.transport.cipher.Cipher;

/**
 * All BlockCiphers supported by SSH according to the following RFCs:
 *
 * <ul>
 *   <li>https://tools.ietf.org/html/rfc4344#section-3.1</li>
 *   <li>https://tools.ietf.org/html/rfc4253#section-6.3</li>
 *   <li>TODO: https://tools.ietf.org/html/rfc5647</li>
 * </ul>
 *
 * Some of the Ciphers are still implemented in net.schmizz.sshj.transport.cipher.*. These are deprecated and scheduled to be removed.
 */
@SuppressWarnings("PMD.MethodNamingConventions")
public class BlockCiphers {

    public static final String COUNTER_MODE = "CTR";
    public static final String CIPHER_BLOCK_CHAINING_MODE = "CBC";

    public static Factory AES128CTR() {
        return new Factory(16, 128, "aes128-ctr", "AES", COUNTER_MODE);
    }
    public static Factory AES192CTR() {
        return new Factory(16, 192, "aes192-ctr", "AES", COUNTER_MODE);
    }
    public static Factory AES256CTR() {
        return new Factory(16, 256, "aes256-ctr", "AES", COUNTER_MODE);
    }
    public static Factory AES128CBC() {
        return new Factory(16, 128, "aes128-cbc", "AES", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory AES192CBC() {
        return new Factory(16, 192, "aes192-cbc", "AES", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory AES256CBC() {
        return new Factory(16, 256, "aes256-cbc", "AES", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory BlowfishCTR() {
        return new Factory(8, 256, "blowfish-ctr", "Blowfish", COUNTER_MODE);
    }
    public static Factory BlowfishCBC() {
        return new Factory(8, 128, "blowfish-cbc", "Blowfish", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory Twofish128CTR() {
        return new Factory(16, 128, "twofish128-ctr", "Twofish", COUNTER_MODE);
    }
    public static Factory Twofish192CTR() {
        return new Factory(16, 192, "twofish192-ctr", "Twofish", COUNTER_MODE);
    }
    public static Factory Twofish256CTR() {
        return new Factory(16, 256, "twofish256-ctr", "Twofish", COUNTER_MODE);
    }
    public static Factory Twofish128CBC() {
        return new Factory(16, 128, "twofish128-cbc", "Twofish", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory Twofish192CBC() {
        return new Factory(16, 192, "twofish192-cbc", "Twofish", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory Twofish256CBC() {
        return new Factory(16, 256, "twofish256-cbc", "Twofish", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory TwofishCBC() {
        return new Factory(16, 256, "twofish-cbc", "Twofish", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory Serpent128CTR() {
        return new Factory(16, 128, "serpent128-ctr", "Serpent", COUNTER_MODE);
    }
    public static Factory Serpent192CTR() {
        return new Factory(16, 192, "serpent192-ctr", "Serpent", COUNTER_MODE);
    }
    public static Factory Serpent256CTR() {
        return new Factory(16, 256, "serpent256-ctr", "Serpent", COUNTER_MODE);
    }
    public static Factory Serpent128CBC() {
        return new Factory(16, 128, "serpent128-cbc", "Serpent", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory Serpent192CBC() {
        return new Factory(16, 192, "serpent192-cbc", "Serpent", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory Serpent256CBC() {
        return new Factory(16, 256, "serpent256-cbc", "Serpent", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory IDEACTR() {
        return new Factory(8, 128, "idea-ctr", "IDEA", COUNTER_MODE);
    }
    public static Factory IDEACBC() {
        return new Factory(8, 128, "idea-cbc", "IDEA", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory Cast128CTR() {
        return new Factory(8, 128, "cast128-ctr", "CAST5", COUNTER_MODE);
    }
    public static Factory Cast128CBC() {
        return new Factory(8, 128, "cast128-cbc", "CAST5", CIPHER_BLOCK_CHAINING_MODE);
    }
    public static Factory TripleDESCTR() {
        return new Factory(8, 192, "3des-ctr", "DESede", COUNTER_MODE);
    }
    public static Factory TripleDESCBC() {
        return new Factory(8, 192, "3des-cbc", "DESede", CIPHER_BLOCK_CHAINING_MODE);
    }

    /** Named factory for BlockCipher */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Cipher> {

        private int keysize;
        private String cipher;
        private String mode;
        private String name;
        private int ivsize;

        /**
         * @param ivsize
         * @param keysize The keysize used in bits.
         * @param name
         * @param cipher
         * @param mode
         */
        public Factory(int ivsize, int keysize, String name, String cipher, String mode) {
            this.name = name;
            this.keysize = keysize;
            this.cipher = cipher;
            this.mode = mode;
            this.ivsize = ivsize;
        }

        @Override
        public Cipher create() {
            return new BlockCipher(ivsize, keysize / 8, cipher, cipher + "/" + mode + "/NoPadding");
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return getName();
        }
    }


}
