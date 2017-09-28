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

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.ByteArrayUtils;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

import java.security.*;

/**
 * An abstract class for {@link Signature} that implements common functionality.
 */
public abstract class AbstractSignature
        implements Signature {

    protected final java.security.Signature signature;

    protected AbstractSignature(String algorithm) {
        try {
            this.signature = SecurityUtils.getSignature(algorithm);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }

    protected AbstractSignature(java.security.Signature signatureEngine) {
        this.signature = signatureEngine;
    }

    @Override
    public void initVerify(PublicKey publicKey) {
        try {
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public void initSign(PrivateKey privateKey) {
        try {
            signature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public void update(byte[] foo) {
        update(foo, 0, foo.length);
    }

    @Override
    public void update(byte[] foo, int off, int len) {
        try {
            signature.update(foo, off, len);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public byte[] sign() {
        try {
            return signature.sign();
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    /**
     * Only used by ssh-dsa and ssh-rsa signatures.
     * It will check whether the signature is of the expected type
     * and return the signature blob
     *
     * @param sig
     * @return
     */
    protected byte[] extractSig(byte[] sig, String expectedKeyAlgorithm) {
        Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(sig);
        try {
            String algo = buffer.readString();
            if (!expectedKeyAlgorithm.equals(algo)) {
                throw new SSHRuntimeException("Expected '" + expectedKeyAlgorithm + "' key algorithm, but got: " + algo);
            }
            return buffer.readBytes();
        } catch (Buffer.BufferException e) {
            throw new SSHRuntimeException(e);
        }
    }

}
