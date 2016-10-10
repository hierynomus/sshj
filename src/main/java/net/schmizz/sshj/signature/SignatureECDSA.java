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

import java.math.BigInteger;
import java.security.SignatureException;

/** ECDSA {@link Signature} */
public class SignatureECDSA
        extends AbstractSignature {

    /** A named factory for ECDSA signature */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureECDSA();
        }

        @Override
        public String getName() {
            return KeyType.ECDSA.toString();
        }

    }

    public SignatureECDSA() {
        super("SHA256withECDSA");
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

        Buffer buf = new Buffer.PlainBuffer();
        buf.putMPInt(new BigInteger(r));
        buf.putMPInt(new BigInteger(s));

        return buf.getCompactData();
    }

    @Override
    public boolean verify(byte[] sig) {
        byte[] r;
        byte[] s;
        try {
            Buffer sigbuf = new Buffer.PlainBuffer(sig);
            final String algo = new String(sigbuf.readBytes());
            if (!"ecdsa-sha2-nistp256".equals(algo)) {
                throw new SSHRuntimeException(String.format("Signature :: ecdsa-sha2-nistp256 expected, got %s", algo));
            }
            final int rsLen = sigbuf.readUInt32AsInt();
            if (!(sigbuf.available() == rsLen)) {
                throw new SSHRuntimeException("Invalid key length");
            }
            r = sigbuf.readBytes();
            s = sigbuf.readBytes();
        } catch (Exception e) {
            throw new SSHRuntimeException(e);
        }

        int rLen = r.length;
        int sLen = s.length;

        /* We can't have the high bit set, so add an extra zero at the beginning if so. */
        if ((r[0] & 0x80) != 0) {
            rLen++;
        }
        if ((s[0] & 0x80) != 0) {
            sLen++;
        }

        /* Calculate total output length */
        int length = 6 + rLen + sLen;
        byte[] asn1 = new byte[length];

        /* ASN.1 SEQUENCE tag */
        asn1[0] = (byte) 0x30;

        /* Size of SEQUENCE */
        asn1[1] = (byte) (4 + rLen + sLen);

        /* ASN.1 INTEGER tag */
        asn1[2] = (byte) 0x02;

        /* "r" INTEGER length */
        asn1[3] = (byte) rLen;

        /* Copy in the "r" INTEGER */
        System.arraycopy(r, 0, asn1, 4, rLen);

        /* ASN.1 INTEGER tag */
        asn1[rLen + 4] = (byte) 0x02;

        /* "s" INTEGER length */
        asn1[rLen + 5] = (byte) sLen;

        /* Copy in the "s" INTEGER */
        System.arraycopy(s, 0, asn1, (6 + rLen), sLen);


        try {
            return signature.verify(asn1);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }
}
