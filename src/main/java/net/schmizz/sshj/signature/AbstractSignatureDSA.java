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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public abstract class AbstractSignatureDSA extends AbstractSignature {
    protected AbstractSignatureDSA(String algorithm, String signatureName) {
        super(algorithm, signatureName);
    }

    /**
     * Get ASN.1 Signature encoded using DER Sequence of integers
     *
     * @param r DSA Signature R
     * @param s DSA Signature S
     * @return ASN.1 Encoded Signature
     * @throws IOException Thrown when failing to write signature integers
     */
    protected byte[] getAsnEncodedSignature(final BigInteger r, final BigInteger s) throws IOException {
        final ASN1Integer[] integers = new ASN1Integer[] { new ASN1Integer(r), new ASN1Integer(s) };
        final DERSequence sequence = new DERSequence(integers);

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(byteArrayOutputStream, ASN1Encoding.DER);
        asn1OutputStream.writeObject(sequence);
        asn1OutputStream.flush();
        asn1OutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }
}
