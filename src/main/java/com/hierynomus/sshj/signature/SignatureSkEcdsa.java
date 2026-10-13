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

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.encodingrules.der.DERDecoder;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.signature.Signature;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Signature for the {@code sk-ecdsa-sha2-nistp256@openssh.com} FIDO/U2F key type.
 * <p>
 * The authenticator produces an ASN.1 DER ECDSA signature; on the SSH wire it is encoded as the two
 * integers {@code r} and {@code s} as mpints, exactly like a plain {@code ecdsa-sha2-nistp256}
 * signature. This class converts between the two encodings. The verification engine is always
 * SHA-256 (the "sha2-nistp256" of the key type).
 */
public class SignatureSkEcdsa extends AbstractSecurityKeySignature {

    public static class Factory implements net.schmizz.sshj.common.Factory.Named<Signature> {
        @Override
        public String getName() {
            return KeyType.SK_ECDSA.toString();
        }

        @Override
        public Signature create() {
            return new SignatureSkEcdsa();
        }
    }

    public SignatureSkEcdsa() {
        super("SHA256withECDSA", KeyType.SK_ECDSA.toString());
    }

    @Override
    protected byte[] sshSignatureToDevice(byte[] sshRawSignature) throws Buffer.BufferException {
        Buffer.PlainBuffer buf = new Buffer.PlainBuffer(sshRawSignature);
        BigInteger r = buf.readMPInt();
        BigInteger s = buf.readMPInt();
        try {
            return encodeAsnSignature(r, s);
        } catch (IOException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    protected byte[] deviceSignatureToSsh(byte[] derSignature) {
        ByteArrayInputStream bais = new ByteArrayInputStream(derSignature);
        ASN1InputStream asn1InputStream = new ASN1InputStream(new DERDecoder(), bais);
        try {
            ASN1Sequence sequence = asn1InputStream.readObject();
            BigInteger r = ((ASN1Integer) sequence.get(0)).getValue();
            BigInteger s = ((ASN1Integer) sequence.get(1)).getValue();
            return new Buffer.PlainBuffer().putMPInt(r).putMPInt(s).getCompactData();
        } finally {
            IOUtils.closeQuietly(asn1InputStream, bais);
        }
    }
}
