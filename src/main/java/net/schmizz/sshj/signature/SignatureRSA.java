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
import java.util.Date;

/** RSA {@link Signature} */
public class SignatureRSA
        extends AbstractSignature {

    /** A named factory for RSA {@link Signature} */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureRSA(KeyType.RSA.toString());
        }

        @Override
        public String getName() {
            return KeyType.RSA.toString();
        }

    }

    /** A named factory for RSA {@link Signature} */
    public static class FactoryCERT
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureRSA(KeyType.RSA_CERT.toString());
        }

        @Override
        public String getName() {
            return KeyType.RSA_CERT.toString();
        }

    }

    private String keyTypeName;


    public SignatureRSA(String keyTypeName) {
        super("SHA1withRSA");
        this.keyTypeName = keyTypeName;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void initVerify(PublicKey publicKey) {
        try {
            if (this.keyTypeName.equals(KeyType.RSA_CERT.toString()) && publicKey instanceof Certificate) {
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
        sig = extractSig(sig, KeyType.RSA.toString());
        try {
            return signature.verify(sig);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }
}
