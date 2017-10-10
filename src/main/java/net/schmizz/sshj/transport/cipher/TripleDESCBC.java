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

import com.hierynomus.sshj.transport.cipher.BlockCiphers;

/**
 * {@code 3des-cbc} cipher
 *
 * @deprecated Use {@link BlockCiphers#TripleDESCBC()}
 */
@Deprecated
public class TripleDESCBC
        extends BlockCipher {

    /** Named factory for TripleDESCBC Cipher */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Cipher> {

        @Override
        public Cipher create() {
            return new TripleDESCBC();
        }

        @Override
        public String getName() {
            return "3des-cbc";
        }

        @Override
        public String toString() {
            return getName();
        }
    }

    public TripleDESCBC() {
        super(8, 24, "DESede", "DESede/CBC/NoPadding");
    }

}
