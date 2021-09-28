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
