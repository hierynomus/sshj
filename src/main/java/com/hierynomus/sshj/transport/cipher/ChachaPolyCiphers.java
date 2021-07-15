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

public class ChachaPolyCiphers {

    public static Factory CHACHA_POLY_OPENSSH() {
        return new Factory(16, 512, "chacha20-poly1305@openssh.com", "ChaCha20");
    }

    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Cipher> {

        private final int authSize;
        private final int keySize;
        private final String name;
        private final String cipher;

        public Factory(int authSize, int keySize, String name, String cipher) {
            this.authSize = authSize;
            this.keySize = keySize;
            this.name = name;
            this.cipher = cipher;
        }

        @Override
        public Cipher create() {
            return new ChachaPolyCipher(authSize, keySize / 8, cipher);
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
