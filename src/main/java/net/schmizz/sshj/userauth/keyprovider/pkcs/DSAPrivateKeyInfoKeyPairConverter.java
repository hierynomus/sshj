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
package net.schmizz.sshj.userauth.keyprovider.pkcs;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.openssl.PEMKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Key Pair Converter from DSA Private Key Information to PEM Key Pair
 */
class DSAPrivateKeyInfoKeyPairConverter implements KeyPairConverter<PrivateKeyInfo> {
    private static final Logger logger = LoggerFactory.getLogger(DSAPrivateKeyInfoKeyPairConverter.class);

    private static final int P_INDEX = 0;

    private static final int Q_INDEX = 1;

    private static final int G_INDEX = 2;

    /**
     * Get PEM Key Pair calculating DSA Public Key from DSA Private Key Information
     *
     * @param privateKeyInfo DSA Private Key Information
     * @return PEM Key Pair
     * @throws IOException Thrown on Public Key parsing failures
     */
    @Override
    public PEMKeyPair getKeyPair(final PrivateKeyInfo privateKeyInfo) throws IOException {
        Objects.requireNonNull(privateKeyInfo, "Private Key Info required");
        final AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        final ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        if (X9ObjectIdentifiers.id_dsa.equals(algorithm)) {
            logger.debug("DSA Algorithm Found [{}]", algorithm);
        } else {
            throw new IllegalArgumentException(String.format("DSA Algorithm OID required [%s]", algorithm));
        }
        final ASN1Integer encodedPublicKey = getEncodedPublicKey(privateKeyInfo);
        final SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, encodedPublicKey);
        return new PEMKeyPair(subjectPublicKeyInfo, privateKeyInfo);
    }

    /**
     * Get ASN.1 Encoded Public Key calculated according to RFC 6979 Section 2.2
     *
     * @param privateKeyInfo DSA Private Key Information
     * @return ASN.1 Encoded DSA Public Key
     * @throws IOException Thrown on failures parsing private key
     */
    private ASN1Integer getEncodedPublicKey(final PrivateKeyInfo privateKeyInfo) throws IOException {
        final ASN1Integer privateKey = ASN1Integer.getInstance(privateKeyInfo.parsePrivateKey());
        final AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        final DSAParameters dsaParameters = getDsaParameters(algorithmIdentifier);
        final BigInteger publicKey = dsaParameters.getG().modPow(privateKey.getValue(), dsaParameters.getP());
        return new ASN1Integer(publicKey);
    }

    private DSAParameters getDsaParameters(final AlgorithmIdentifier algorithmIdentifier) {
        final ASN1Sequence sequence = ASN1Sequence.getInstance(algorithmIdentifier.getParameters());
        final ASN1Integer p = ASN1Integer.getInstance(sequence.getObjectAt(P_INDEX));
        final ASN1Integer q = ASN1Integer.getInstance(sequence.getObjectAt(Q_INDEX));
        final ASN1Integer g = ASN1Integer.getInstance(sequence.getObjectAt(G_INDEX));
        return new DSAParameters(p.getValue(), q.getValue(), g.getValue());
    }
}
