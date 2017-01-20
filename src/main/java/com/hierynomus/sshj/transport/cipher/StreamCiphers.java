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

/**
 * Implementations of the Stream Ciphers that are defined in the RFCs
 *
 * - https://tools.ietf.org/html/rfc4253#section-6.3
 * - https://tools.ietf.org/html/rfc4345
 */
@SuppressWarnings("PMD.MethodNamingConventions")
public class StreamCiphers {

    public static Factory Arcfour() {
        return new Factory(128, "arcfour", "ARCFOUR", "ECB");
    }
    public static Factory Arcfour128() {
        return new Factory(128, "arcfour128", "RC4", "ECB");
    }
    public static Factory Arcfour256() {
        return new Factory(256, "arcfour256", "RC4", "ECB");
    }

    /** Named factory for BlockCipher */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Cipher> {

        private int keysize;
        private String cipher;
        private String mode;
        private String name;

        /**
         * @param keysize The keysize used in bits.
         * @param name
         * @param cipher
         * @param mode
         */
        public Factory(int keysize, String name, String cipher, String mode) {
            this.name = name;
            this.keysize = keysize;
            this.cipher = cipher;
            this.mode = mode;
        }

        @Override
        public Cipher create() {
            return new StreamCipher(keysize / 8, cipher, cipher + "/" + mode + "/NoPadding");
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
