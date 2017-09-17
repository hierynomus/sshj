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

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;

import java.security.SignatureException;

/** DSA {@link Signature} */
public class SignatureDSA
        extends AbstractSignature {

    /** A named factory for DSA signature */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureDSA();
        }

        @Override
        public String getName() {
            return KeyType.DSA.toString();
        }

    }

    public SignatureDSA() {
        super("SHA1withDSA");
    }

    @Override
    public byte[] encode(byte[] sig) {
        return fromASN1toMPINT(sig);
    }

    @Override
    public boolean verify(byte[] sig) {
        sig = extractSig(sig);
        try {
            return signature.verify(fromMPINTtoASN1(sig));
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    /**
     * Converts from ASN.1 (JCA) to mpint (SSH).
     *
     * @param sig
     *            - signature encoded in ASN.1
     * @return signature encoded in mpint
     * @see <a href="https://www.ietf.org/rfc/rfc4251.txt">RFC 4251</a>
     */
    byte[] fromASN1toMPINT(final byte[] sig) {
        // sig is in ASN.1
        // SEQUENCE::={ r INTEGER, s INTEGER }

        byte[] r = computeMPINT(sig, 3);
        byte[] s = computeMPINT(sig, 4 + r.length + 1);

        byte[] result = new byte[40];

        // result must be 40 bytes, but length of r and s may not be 20 bytes

        int r_copylen = (r.length < 20) ? r.length : 20;
        int s_copylen = (s.length < 20) ? s.length : 20;

        System.arraycopy(r, r.length - r_copylen, result, 20 - r_copylen, r_copylen);
        System.arraycopy(s, s.length - s_copylen, result, 40 - s_copylen, s_copylen);

        return result;
    }

    private byte[] computeMPINT(final byte[] sig, final int index) {
        int len = sig[index] & 0xff;
        byte[] result = new byte[len];
        System.arraycopy(sig, index + 1, result, 0, result.length);
        return result;
    }

    /**
     * Converts from mpint (SSH) to ASN.1 (JCA).
     *
     * @param sig
     *            - signature encoded in mpint
     * @return signature encoded in ASN.1
     * @author Jurrie Overgoor &lt;jsch@jurr.org&gt;
     * @see <a href="https://www.ietf.org/rfc/rfc4251.txt">RFC 4251</a>
     */
    byte[] fromMPINTtoASN1(final byte[] sig) {

        int lenFirst = computeASN1Length(sig, 0);
        int lenSecond = computeASN1Length(sig, 20);

        int maxLenFirst = Math.min(lenFirst, 20);
        int maxLenSecond = Math.min(lenSecond, 20);

        int length = 6 + lenFirst + lenSecond;
        byte[] result = new byte[length];
        result[0] = (byte) 0x30; // ASN.1 SEQUENCE
        result[1] = (byte) (lenFirst + lenSecond + 4); // ASN.1 length of sequence
        result[2] = (byte) 0x02; // ASN.1 INTEGER
        result[3] = (byte) lenFirst; // ASN.1 length of integer
        System.arraycopy(sig, 20 - maxLenFirst, result, 4 + (lenFirst > 20 ? 1 : 0), maxLenFirst);
        result[4 + result[3]] = (byte) 0x02; // ASN.1 INTEGER
        result[5 + result[3]] = (byte) lenSecond; // ASN.1 length of integer
        System.arraycopy(sig, 20 + 20 - maxLenSecond, result, 6 + result[3] + (lenSecond > 20 ? 1 : 0), maxLenSecond);

        return result;
    }

    private int computeASN1Length(final byte[] sig, final int index) {
        int length = 20;
        if ((sig[index] & 0x80) != 0) {
            // ASN.1 would see this as negative INTEGER, so we add a leading 0x00 byte.
            length++;
        } else {
            while (sig[index + 20 - length] == 0 && (sig[index + 20 - length + 1] & 0x80) != 0x80) {
                // The mpint starts with redundant 0x00 bytes.
                length--;
            }
        }
        return length;
    }

}
