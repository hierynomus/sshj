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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;

/**
 * Key Pair Converter from RSA Private Key Information to PEM Key Pair
 */
class RSAPrivateKeyInfoKeyPairConverter implements KeyPairConverter<PrivateKeyInfo> {
    private static final Logger logger = LoggerFactory.getLogger(RSAPrivateKeyInfoKeyPairConverter.class);

    /**
     * Get PEM Key Pair parsing RSA Public Key attributes from RSA Private Key Information
     *
     * @param privateKeyInfo RSA Private Key Information
     * @return PEM Key Pair
     * @throws IOException Thrown on Public Key parsing failures
     */
    @Override
    public PEMKeyPair getKeyPair(final PrivateKeyInfo privateKeyInfo) throws IOException {
        Objects.requireNonNull(privateKeyInfo, "Private Key Info required");
        final AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        final ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)) {
            logger.debug("RSA Algorithm Found [{}]", algorithm);
        } else {
            throw new IllegalArgumentException(String.format("RSA Algorithm OID required [%s]", algorithm));
        }

        final RSAPublicKey rsaPublicKey = getRsaPublicKey(privateKeyInfo);
        final SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, rsaPublicKey);
        return new PEMKeyPair(subjectPublicKeyInfo, privateKeyInfo);
    }

    private RSAPublicKey getRsaPublicKey(final PrivateKeyInfo privateKeyInfo) throws IOException {
        final RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(privateKeyInfo.parsePrivateKey());
        return new RSAPublicKey(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent());
    }
}
