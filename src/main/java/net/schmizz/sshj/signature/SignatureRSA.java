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
package net.schmizz.sshj.signature;

import com.hierynomus.sshj.userauth.certificate.Certificate;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;

/** RSA {@link Signature} */
public class SignatureRSA
        extends AbstractSignature {

    /** A named factory for RSA {@link Signature} */
    public static class FactorySSHRSA
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureRSA("SHA1withRSA", KeyType.RSA, KeyType.RSA.toString());
        }

        @Override
        public String getName() {
            return KeyType.RSA.toString();
        }
    }

    /** A named factory for RSA {@link Signature} */
    public static class FactoryRSASHA256
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureRSA("SHA256withRSA", KeyType.RSA, "rsa-sha2-256");
        }

        @Override
        public String getName() {
            return "rsa-sha2-256";
        }
    }
    /** A named factory for RSA {@link Signature} */
    public static class FactoryRSASHA512
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureRSA("SHA512withRSA", KeyType.RSA, "rsa-sha2-512");
        }

        @Override
        public String getName() {
            return "rsa-sha2-512";
        }
    }

    /** A named factory for RSA {@link Signature} */
    public static class FactoryCERT
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureRSA("SHA1withRSA", KeyType.RSA_CERT, KeyType.RSA.toString());
        }

        @Override
        public String getName() {
            return KeyType.RSA_CERT.toString();
        }

    }

    private KeyType keyType;


    public SignatureRSA(String algorithm, KeyType keyType, String name) {
        super(algorithm, name);
        this.keyType = keyType;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void initVerify(PublicKey publicKey) {
        try {
            if (this.keyType.equals(KeyType.RSA_CERT) && publicKey instanceof Certificate) {
                signature.initVerify(((Certificate<PublicKey>) publicKey).getKey());
            } else {
                signature.initVerify(publicKey);
            }
        } catch (InvalidKeyException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public byte[] encode(byte[] signature) {
        return signature;
    }

    @Override
    public boolean verify(byte[] sig) {
        sig = extractSig(sig, getSignatureName());
        try {
            return signature.verify(sig);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }
}
