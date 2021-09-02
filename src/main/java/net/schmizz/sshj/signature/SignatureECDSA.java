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
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;

/** ECDSA {@link Signature} */
public class SignatureECDSA extends AbstractSignatureDSA {

    /** A named factory for ECDSA-256 signature */
    public static class Factory256 implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureECDSA("SHA256withECDSA", KeyType.ECDSA256.toString());
        }

        @Override
        public String getName() {
            return KeyType.ECDSA256.toString();
        }

    }

    /** A named factory for ECDSA-384 signature */
    public static class Factory384 implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureECDSA("SHA384withECDSA", KeyType.ECDSA384.toString());
        }

        @Override
        public String getName() {
            return KeyType.ECDSA384.toString();
        }

    }

    /** A named factory for ECDSA-521 signature */
    public static class Factory521 implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureECDSA("SHA512withECDSA", KeyType.ECDSA521.toString());
        }

        @Override
        public String getName() {
            return KeyType.ECDSA521.toString();
        }

    }

    private final String keyTypeName;

    public SignatureECDSA(String algorithm, String keyTypeName) {
        super(algorithm, keyTypeName);
        this.keyTypeName = keyTypeName;
    }

    @Override
    public byte[] encode(byte[] sig) {
        ByteArrayInputStream bais = new ByteArrayInputStream(sig);
        final ASN1InputStream asn1InputStream = new ASN1InputStream(bais);
        try {
            ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
            ASN1Integer r = (ASN1Integer) sequence.getObjectAt(0);
            ASN1Integer s = (ASN1Integer) sequence.getObjectAt(1);
            Buffer.PlainBuffer buf = new Buffer.PlainBuffer();
            buf.putMPInt(r.getValue());
            buf.putMPInt(s.getValue());

            return buf.getCompactData();
        } catch (final IOException e) {
            throw new SSHRuntimeException("Signature Encoding Failed", e);
        } finally {
            IOUtils.closeQuietly(asn1InputStream, bais);
        }
    }

    @Override
    public boolean verify(byte[] sig) {
        try {
            byte[] sigBlob = extractSig(sig, keyTypeName);
            final Buffer.PlainBuffer buffer = new Buffer.PlainBuffer(sigBlob);
            final BigInteger r = buffer.readMPInt();
            final BigInteger s = buffer.readMPInt();
            final byte[] asnEncodedSignature = getAsnEncodedSignature(r, s);
            return signature.verify(asnEncodedSignature);
        } catch (SignatureException e) {
            throw new SSHRuntimeException("Signature Verification Failed", e);
        } catch (IOException e) {
            throw new SSHRuntimeException(e);
        }
    }
}
