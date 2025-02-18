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
package net.schmizz.sshj.common;

import com.hierynomus.sshj.common.KeyAlgorithm;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Objects;

/**
 * Factory for generating Elliptic Curve Keys using Java Security components for NIST Curves
 */
public class ECDSAKeyFactory {

    private ECDSAKeyFactory() {

    }

    /**
     * Get Elliptic Curve Private Key for private key value and Curve Name
     *
     * @param privateKeyInteger Private Key
     * @param ecdsaCurve Elliptic Curve
     * @return Elliptic Curve Private Key
     * @throws GeneralSecurityException Thrown on failure to create parameter specification
     */
    public static PrivateKey getPrivateKey(final BigInteger privateKeyInteger, final ECDSACurve ecdsaCurve) throws GeneralSecurityException {
        Objects.requireNonNull(privateKeyInteger, "Private Key integer required");
        Objects.requireNonNull(ecdsaCurve, "Curve required");

        final ECParameterSpec parameterSpec = getParameterSpec(ecdsaCurve);
        final ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKeyInteger, parameterSpec);

        final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyAlgorithm.ECDSA);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Get Elliptic Curve Public Key for public key value and Curve Name
     *
     * @param point Public Key point
     * @param ecdsaCurve Elliptic Curve
     * @return Elliptic Curve Public Key
     * @throws GeneralSecurityException Thrown on failure to create parameter specification
     */
    public static PublicKey getPublicKey(final ECPoint point, final ECDSACurve ecdsaCurve) throws GeneralSecurityException {
        Objects.requireNonNull(point, "Elliptic Curve Point required");
        Objects.requireNonNull(ecdsaCurve, "Curve required");

        final ECParameterSpec parameterSpec = getParameterSpec(ecdsaCurve);
        final ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, parameterSpec);

        final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyAlgorithm.ECDSA);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private static ECParameterSpec getParameterSpec(final ECDSACurve ecdsaCurve) throws GeneralSecurityException {
        final ECGenParameterSpec genParameterSpec = new ECGenParameterSpec(ecdsaCurve.getCurveName());
        final AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(KeyAlgorithm.EC_KEYSTORE);
        algorithmParameters.init(genParameterSpec);
        return algorithmParameters.getParameterSpec(ECParameterSpec.class);
    }
}
