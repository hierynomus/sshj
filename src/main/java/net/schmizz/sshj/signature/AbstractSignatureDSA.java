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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.primitive.ASN1Integer;

import net.schmizz.sshj.common.IOUtils;

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
    @SuppressWarnings("rawtypes")
    protected byte[] encodeAsnSignature(final BigInteger r, final BigInteger s) throws IOException {
        List<ASN1Object> vector = new ArrayList<ASN1Object>();
        vector.add(new com.hierynomus.asn1.types.primitive.ASN1Integer(r));
        vector.add(new ASN1Integer(s));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream asn1OutputStream = new ASN1OutputStream(new DEREncoder(), baos);
        try {
            asn1OutputStream.writeObject(new ASN1Sequence(vector));
            asn1OutputStream.flush();
        } finally {
            IOUtils.closeQuietly(asn1OutputStream);
        }

        return baos.toByteArray();

    }
}
