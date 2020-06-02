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
package com.hierynomus.sshj.key;

import com.hierynomus.sshj.signature.SignatureEdDSA;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;

public class EdDSAKeyAlgorithm extends AbstractKeyAlgorithm {
    public static class Factory implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public String getName() {
            return KeyType.ED25519.toString();
        }

        @Override
        public KeyAlgorithm create() {
            return new EdDSAKeyAlgorithm(KeyType.ED25519.toString(), new SignatureEdDSA.Factory(), KeyType.ED25519);
        }
    }

    public EdDSAKeyAlgorithm(String keyAlgorithm, Factory.Named<Signature> signature, KeyType keyFormat) {
        super(keyAlgorithm, signature, keyFormat);
    }
}
