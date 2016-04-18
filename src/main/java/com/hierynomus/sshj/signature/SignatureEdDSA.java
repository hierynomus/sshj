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
package com.hierynomus.sshj.signature;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.signature.Signature;

import java.security.*;

public class SignatureEdDSA implements Signature {
    public static class Factory implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public String getName() {
            return KeyType.ED25519.toString();
        }

        @Override
        public Signature create() {
            return new SignatureEdDSA();
        }
    }

    final EdDSAEngine engine;

    protected SignatureEdDSA() {
        try {
            engine = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        } catch (NoSuchAlgorithmException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public void init(PublicKey pubkey, PrivateKey prvkey) {
        try {
            if (pubkey != null) {
                engine.initVerify(pubkey);
            }

            if (prvkey != null) {
                engine.initSign(prvkey);
            }
        } catch (InvalidKeyException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public void update(byte[] H) {
        update(H, 0, H.length);
    }

    @Override
    public void update(byte[] H, int off, int len) {
        try {
            engine.update(H, off, len);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public byte[] sign() {
        try {
            return engine.sign();
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public byte[] encode(byte[] signature) {
        return signature;
    }

    @Override
    public boolean verify(byte[] sig) {
        try {
            Buffer.PlainBuffer plainBuffer = new Buffer.PlainBuffer(sig);
            String algo = plainBuffer.readString();
            if (!"ssh-ed25519".equals(algo)) {
                throw new SSHRuntimeException("Expected 'ssh-ed25519' key algorithm, but was: " + algo);
            }
            byte[] bytes = plainBuffer.readBytes();
            return engine.verify(bytes);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        } catch (Buffer.BufferException e) {
            throw new SSHRuntimeException(e);
        }
    }
}
