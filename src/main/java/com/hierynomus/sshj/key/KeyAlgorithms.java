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
import net.schmizz.sshj.signature.SignatureDSA;
import net.schmizz.sshj.signature.SignatureECDSA;
import net.schmizz.sshj.signature.SignatureRSA;

public class KeyAlgorithms {

    public static Factory SSHRSA() { return new Factory("ssh-rsa", new SignatureRSA.FactorySSHRSA(), KeyType.RSA); }
    public static Factory SSHRSACertV01() { return new Factory("ssh-rsa-cert-v01@openssh.com", new SignatureRSA.FactoryCERT(), KeyType.RSA_CERT); }
    public static Factory RSASHA256() { return new Factory("rsa-sha2-256", new SignatureRSA.FactoryRSASHA256(), KeyType.RSA); }
    public static Factory RSASHA512() { return new Factory("rsa-sha2-512", new SignatureRSA.FactoryRSASHA512(), KeyType.RSA); }
    public static Factory SSHDSA() { return new Factory(KeyType.DSA.toString(), new SignatureDSA.Factory(), KeyType.DSA); }
    public static Factory SSHDSSCertV01() { return new Factory(KeyType.DSA_CERT.toString(), new SignatureDSA.Factory(), KeyType.DSA_CERT); }
    public static Factory ECDSASHANistp256() { return new Factory(KeyType.ECDSA256.toString(), new SignatureECDSA.Factory256(), KeyType.ECDSA256); }
    public static Factory ECDSASHANistp256CertV01() { return new Factory(KeyType.ECDSA256_CERT.toString(), new SignatureECDSA.Factory256(), KeyType.ECDSA256_CERT); }
    public static Factory ECDSASHANistp384() { return new Factory(KeyType.ECDSA384.toString(), new SignatureECDSA.Factory384(), KeyType.ECDSA384); }
    public static Factory ECDSASHANistp384CertV01() { return new Factory(KeyType.ECDSA384_CERT.toString(), new SignatureECDSA.Factory384(), KeyType.ECDSA384_CERT); }
    public static Factory ECDSASHANistp521() { return new Factory(KeyType.ECDSA521.toString(), new SignatureECDSA.Factory521(), KeyType.ECDSA521); }
    public static Factory ECDSASHANistp521CertV01() { return new Factory(KeyType.ECDSA521_CERT.toString(), new SignatureECDSA.Factory521(), KeyType.ECDSA521_CERT); }
    public static Factory EdDSA25519() { return new Factory(KeyType.ED25519.toString(), new SignatureEdDSA.Factory(), KeyType.ED25519); }
    public static Factory EdDSA25519CertV01() { return new Factory(KeyType.ED25519_CERT.toString(), new SignatureEdDSA.Factory(), KeyType.ED25519_CERT); }

    public static class Factory implements net.schmizz.sshj.common.Factory.Named<KeyAlgorithm> {

        private final String algorithmName;
        private final Named<Signature> signatureFactory;
        private final KeyType keyType;

        public Factory(String algorithmName, Named<Signature> signatureFactory, KeyType keyType) {
            this.algorithmName = algorithmName;
            this.signatureFactory = signatureFactory;
            this.keyType = keyType;
        }

        @Override
        public String getName() {
            return algorithmName;
        }

        public KeyType getKeyType() {
            return keyType;
        }

        @Override
        public KeyAlgorithm create() {
            return new BaseKeyAlgorithm(algorithmName, signatureFactory, keyType);
        }

        @Override
        public String toString() {
            return algorithmName;
        }
    }
}
