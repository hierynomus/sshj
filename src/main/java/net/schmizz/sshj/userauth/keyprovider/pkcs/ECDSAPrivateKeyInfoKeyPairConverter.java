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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.openssl.PEMKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Key Pair Converter from ECDSA Private Key Information to PEM Key Pair
 */
class ECDSAPrivateKeyInfoKeyPairConverter implements KeyPairConverter<PrivateKeyInfo> {
    private static final Logger logger = LoggerFactory.getLogger(ECDSAPrivateKeyInfoKeyPairConverter.class);

    private static final boolean POINT_COMPRESSED = false;

    /**
     * Get PEM Key Pair calculating ECDSA Public Key from ECDSA Private Key Information
     *
     * @param privateKeyInfo ECDSA Private Key Information
     * @return PEM Key Pair
     * @throws IOException Thrown on Public Key parsing failures
     */
    @Override
    public PEMKeyPair getKeyPair(final PrivateKeyInfo privateKeyInfo) throws IOException {
        Objects.requireNonNull(privateKeyInfo, "Private Key Info required");
        final AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        final ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
            logger.debug("ECDSA Algorithm Found [{}]", algorithm);
        } else {
            throw new IllegalArgumentException(String.format("ECDSA Algorithm OID required [%s]", algorithm));
        }
        final byte[] encodedPublicKey = getEncodedPublicKey(privateKeyInfo);
        final SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, encodedPublicKey);
        return new PEMKeyPair(subjectPublicKeyInfo, privateKeyInfo);
    }

    /**
     * Get Encoded Elliptic Curve Public Key calculated according to RFC 6979 Section 2.2
     *
     * @param privateKeyInfo ECDSA Private Key Information
     * @return Encoded Elliptic Curve Public Key
     * @throws IOException Thrown on failures parsing private key
     */
    private byte[] getEncodedPublicKey(final PrivateKeyInfo privateKeyInfo) throws IOException {
        final X9ECParameters parameters = getParameters(privateKeyInfo.getPrivateKeyAlgorithm());
        final ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
        final ECPoint publicKey = getPublicKey(parameters, ecPrivateKey.getKey());
        return publicKey.getEncoded(POINT_COMPRESSED);
    }

    private X9ECParameters getParameters(final AlgorithmIdentifier algorithmIdentifier) {
        final ASN1ObjectIdentifier encodedParameters = ASN1ObjectIdentifier.getInstance(algorithmIdentifier.getParameters());
        return ECUtil.getNamedCurveByOid(encodedParameters);
    }

    private ECPoint getPublicKey(final X9ECParameters parameters, final BigInteger privateKey) {
        final ECMultiplier multiplier = new FixedPointCombMultiplier();
        return multiplier.multiply(parameters.getG(), privateKey);
    }
}
