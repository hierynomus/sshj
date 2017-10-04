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
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;

/** ECDSA {@link Signature} */
public class SignatureECDSA extends AbstractSignature {

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

    private String keyTypeName;

    public SignatureECDSA(String algorithm, String keyTypeName) {
        super(algorithm);
        this.keyTypeName = keyTypeName;
    }

    @Override
    public byte[] encode(byte[] sig) {
        int rIndex = 3;
        int rLen = sig[rIndex++] & 0xff;
        byte[] r = new byte[rLen];
        System.arraycopy(sig, rIndex, r, 0, r.length);

        int sIndex = rIndex + rLen + 1;
        int sLen = sig[sIndex++] & 0xff;
        byte[] s = new byte[sLen];
        System.arraycopy(sig, sIndex, s, 0, s.length);

        System.arraycopy(sig, 4, r, 0, rLen);
        System.arraycopy(sig, 6 + rLen, s, 0, sLen);

        Buffer.PlainBuffer buf = new Buffer.PlainBuffer();
        buf.putMPInt(new BigInteger(r));
        buf.putMPInt(new BigInteger(s));

        return buf.getCompactData();
    }

    @Override
    public boolean verify(byte[] sig) {
        try {
            byte[] sigBlob = extractSig(sig, keyTypeName);
            return signature.verify(asnEncode(sigBlob));
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        } catch (IOException e) {
            throw new SSHRuntimeException(e);
        }
    }

    /**
     * Encodes the signature as a DER sequence (ASN.1 format).
     */
    private byte[] asnEncode(byte[] sigBlob) throws IOException {
        Buffer.PlainBuffer sigbuf = new Buffer.PlainBuffer(sigBlob);
        byte[] r = sigbuf.readBytes();
        byte[] s = sigbuf.readBytes();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream asnOS = new ASN1OutputStream(baos);

        asnOS.writeObject(new DERSequence(vector));
        asnOS.flush();

        return baos.toByteArray();
    }
}
