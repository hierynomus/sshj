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

import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.signature.SignatureECDSA;

public class ECDSAKeyAlgorithm extends AbstractKeyAlgorithm {
    /** A named factory for ECDSA-256 signature */
    public static class Factory256 implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new ECDSAKeyAlgorithm(KeyType.ECDSA256.toString(), new SignatureECDSA.Factory256(), KeyType.ECDSA256);
        }

        @Override
        public String getName() {
            return KeyType.ECDSA256.toString();
        }

    }

    /** A named factory for ECDSA-384 signature */
    public static class Factory384 implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new ECDSAKeyAlgorithm(KeyType.ECDSA384.toString(), new SignatureECDSA.Factory384(), KeyType.ECDSA384);
        }

        @Override
        public String getName() {
            return KeyType.ECDSA384.toString();
        }

    }

    /** A named factory for ECDSA-521 signature */
    public static class Factory521 implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new ECDSAKeyAlgorithm(KeyType.ECDSA521.toString(), new SignatureECDSA.Factory384(), KeyType.ECDSA521);
        }

        @Override
        public String getName() {
            return KeyType.ECDSA521.toString();
        }

    }

    public ECDSAKeyAlgorithm(String keyAlgorithm, Factory.Named<Signature> signature, KeyType keyFormat) {
        super(keyAlgorithm, signature, keyFormat);
    }
}
