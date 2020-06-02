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
import net.schmizz.sshj.signature.SignatureDSA;

public class DSAKeyAlgorithm extends AbstractKeyAlgorithm {

    /**
     * A named factory for the SSH-DSA key algorithm.
     */
    public static class FactorySSHDSA
            implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new DSAKeyAlgorithm(KeyType.DSA.toString(), new SignatureDSA.Factory(), KeyType.DSA);
        }

        @Override
        public String getName() {
            return KeyType.DSA.toString();
        }

    }

    /**
     * A named factory for the SSH-DSS-CERT key algorithm
     */
    public static class FactorySSHDSSCert
            implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new DSAKeyAlgorithm(KeyType.DSA_CERT.toString(), new SignatureDSA.Factory(), KeyType.DSA_CERT);
        }

        @Override
        public String getName() {
            return KeyType.DSA_CERT.toString();
        }

    }


    public DSAKeyAlgorithm(String keyAlgorithm, Factory.Named<Signature> signature, KeyType keyFormat) {
        super(keyAlgorithm, signature, KeyType.DSA);
    }
}
