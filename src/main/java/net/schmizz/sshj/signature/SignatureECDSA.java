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

import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

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
        super(algorithm, keyTypeName);
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
        BigInteger r = sigbuf.readMPInt();
        BigInteger s = sigbuf.readMPInt();

        List<ASN1Object> vector = new ArrayList<ASN1Object>();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        com.hierynomus.asn1.ASN1OutputStream asn1OutputStream = new com.hierynomus.asn1.ASN1OutputStream(new DEREncoder(), baos);

        asn1OutputStream.writeObject(new ASN1Sequence(vector));
        asn1OutputStream.flush();

        return baos.toByteArray();
    }
}
