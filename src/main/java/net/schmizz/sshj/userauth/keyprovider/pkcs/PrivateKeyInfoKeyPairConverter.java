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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMKeyPair;

import java.io.IOException;
import java.util.Objects;

/**
 * Key Pair Converter for Private Key Information using known Algorithm Object Identifiers
 */
public class PrivateKeyInfoKeyPairConverter implements KeyPairConverter<PrivateKeyInfo> {
    private DSAPrivateKeyInfoKeyPairConverter dsaPrivateKeyInfoKeyPairConverter = new DSAPrivateKeyInfoKeyPairConverter();

    private ECDSAPrivateKeyInfoKeyPairConverter ecdsaPrivateKeyInfoKeyPairConverter = new ECDSAPrivateKeyInfoKeyPairConverter();

    private RSAPrivateKeyInfoKeyPairConverter rsaPrivateKeyInfoKeyPairConverter = new RSAPrivateKeyInfoKeyPairConverter();

    /**
     * Get PEM Key Pair delegating to configured converters based on Algorithm Object Identifier
     *
     * @param privateKeyInfo Private Key Information
     * @return PEM Key Pair
     * @throws IOException Thrown on conversion failures
     */
    @Override
    public PEMKeyPair getKeyPair(final PrivateKeyInfo privateKeyInfo) throws IOException {
        Objects.requireNonNull(privateKeyInfo, "Private Key Info required");
        final AlgorithmIdentifier algorithmIdentifier = privateKeyInfo.getPrivateKeyAlgorithm();
        final ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

        if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)) {
            return rsaPrivateKeyInfoKeyPairConverter.getKeyPair(privateKeyInfo);
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
            return ecdsaPrivateKeyInfoKeyPairConverter.getKeyPair(privateKeyInfo);
        } else if (X9ObjectIdentifiers.id_dsa.equals(algorithm)) {
            return dsaPrivateKeyInfoKeyPairConverter.getKeyPair(privateKeyInfo);
        } else {
            throw new IllegalArgumentException(String.format("Unsupported Algorithm [%s]", algorithm));
        }
    }
}
