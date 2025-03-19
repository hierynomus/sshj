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

import net.schmizz.sshj.transport.cipher.Cipher;

public class GcmCiphers {

    public static final String GALOIS_COUNTER_MODE = "GCM";

    public static Factory AES128GCM() {
        return new Factory(12, 16, 128, "aes128-gcm@openssh.com", "AES", GALOIS_COUNTER_MODE);
    }

    public static Factory AES256GCM() {
        return new Factory(12, 16, 256, "aes256-gcm@openssh.com", "AES", GALOIS_COUNTER_MODE);
    }

    /** Named factory for BlockCipher */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Cipher> {

        private final int keysize;
        private final int authSize;
        private final String cipher;
        private final String mode;
        private final String name;
        private final int ivsize;

        /**
         * @param ivsize
         * @param keysize The keysize used in bits.
         * @param name
         * @param cipher
         * @param mode
         */
        public Factory(int ivsize, int authSize, int keysize, String name, String cipher, String mode) {
            this.name = name;
            this.keysize = keysize;
            this.cipher = cipher;
            this.mode = mode;
            this.ivsize = ivsize;
            this.authSize = authSize;
        }

        @Override
        public Cipher create() {
            return new GcmCipher(ivsize, authSize, keysize / 8, cipher, cipher + "/" + mode + "/NoPadding");
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
