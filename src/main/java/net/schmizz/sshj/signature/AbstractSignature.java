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

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

/** An abstract class for {@link Signature} that implements common functionality. */
public abstract class AbstractSignature
        implements Signature {

    protected final String algorithm;
    protected java.security.Signature signature;

    protected AbstractSignature(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public void init(PublicKey publicKey, PrivateKey privateKey) {
        try {
            signature = SecurityUtils.getSignature(algorithm);
            if (publicKey != null)
                signature.initVerify(publicKey);
            if (privateKey != null)
                signature.initSign(privateKey);
        } catch (GeneralSecurityException e) {
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

    protected byte[] extractSig(byte[] sig) {
        if (sig[0] == 0 && sig[1] == 0 && sig[2] == 0) {
            int i = 0;
            int j = sig[i++] << 24 & 0xff000000
                    | sig[i++] << 16 & 0x00ff0000
                    | sig[i++] << 8 & 0x0000ff00
                    | sig[i++] & 0x000000ff;
            i += j;
            j = sig[i++] << 24 & 0xff000000
                    | sig[i++] << 16 & 0x00ff0000
                    | sig[i++] << 8 & 0x0000ff00
                    | sig[i++] & 0x000000ff;
            byte[] newSig = new byte[j];
            System.arraycopy(sig, i, newSig, 0, j);
            sig = newSig;
        }
        return sig;
    }

}