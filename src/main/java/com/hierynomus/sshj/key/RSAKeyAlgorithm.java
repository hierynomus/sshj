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
import net.schmizz.sshj.signature.SignatureRSA;

public class RSAKeyAlgorithm extends AbstractKeyAlgorithm {

    /**
     * A named factory for the SSH-RSA (SHA1) public key algorithm
     */
    public static class FactorySSHRSA
            implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new RSAKeyAlgorithm("ssh-rsa", new SignatureRSA.FactorySSHRSA(), KeyType.RSA);
        }

        @Override
        public String getName() {
            return "ssh-rsa";
        }
    }

    /**
     * A named factory for the ssh-rsa-cert-v01@openssh.com (SHA1) public key algorithm
     */
    public static class FactorySSHRSACert
            implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new RSAKeyAlgorithm("ssh-rsa-cert-v01@openssh.com", new SignatureRSA.FactoryCERT(), KeyType.RSA_CERT);
        }

        @Override
        public String getName() {
            return "ssh-rsa-cert-v01@openssh.com";
        }
    }

    /**
     * A named factory for the RSA-SHA2-256 public key algorithm
     */
    public static class FactoryRSASHA256
            implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new RSAKeyAlgorithm("rsa-sha2-256", new SignatureRSA.FactoryRSASHA256(), KeyType.RSA);
        }

        @Override
        public String getName() {
            return "rsa-sha2-256";
        }
    }

    /**
     * A named factory for the RSA-SHA2-512 public key algorithm
     */
    public static class FactoryRSASHA512
            implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        @Override
        public KeyAlgorithm create() {
            return new RSAKeyAlgorithm("rsa-sha2-512", new SignatureRSA.FactoryRSASHA512(), KeyType.RSA);
        }

        @Override
        public String getName() {
            return "rsa-sha2-512";
        }
    }

    public RSAKeyAlgorithm(String keyAlgorithm, Factory.Named<Signature> signature, KeyType keyFormat) {
        super(keyAlgorithm, signature, keyFormat);
    }
}
