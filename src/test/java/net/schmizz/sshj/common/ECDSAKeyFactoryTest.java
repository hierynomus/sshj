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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Regression tests for Issue 1018: {@code ECDSAKeyFactory} used to request its {@code KeyFactory}
 * with the algorithm name {@code "ECDSA"}, which is not a portable JCA name - it only resolves at all
 * when BouncyCastle is registered, since that's a BouncyCastle-specific alias for the standard name
 * {@code "EC"}. Where a JVM's default (ambient, no-provider-specified) {@code KeyFactory} and {@code
 * Signature} lookups for these two names land on <em>different</em> providers - which happens whenever
 * BouncyCastle is present but is not the pinned {@link SecurityUtils} provider, as on Android, where
 * {@code Security.addProvider(new BouncyCastleProvider())} is refused because the platform reserves
 * the "BC" provider name for its own bundled fork - the key {@code ECDSAKeyFactory} builds gets
 * rejected by {@code Signature.initVerify}/{@code initSign} with an {@code InvalidKeyException}
 * ("Not an EC key: ECDSA" on a stock OpenJDK; a native DER parsing failure inside Conscrypt on
 * Android). Requesting the portable name {@code "EC"} instead - matching every other EC key
 * construction path in this codebase ({@code ECDH}, {@code PKCS8KeyFile}) - avoids the mismatch
 * entirely, because it never depends on BouncyCastle-specific aliasing.
 */
public class ECDSAKeyFactoryTest {

    /**
     * The JDK's own built-in EC provider. Explicitly pinning verification/signing to this provider -
     * rather than using the ambient, no-provider-specified {@code Signature.getInstance(algorithm)} -
     * is what makes this test deterministic: the ambient lookup can silently paper over the bug by
     * falling back to a differently-provided key's own provider when one is registered (as observed
     * while developing this test, with BouncyCastle installed), which is precisely the graceful
     * fallback that Android's Conscrypt-based stack does not perform, per Issue 1018.
     */
    private static final String NATIVE_EC_PROVIDER = "SunEC";

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void getPublicKeyReportsThePortableAlgorithmName(ECDSACurve curve) throws GeneralSecurityException {
        PublicKey publicKey = ECDSAKeyFactory.getPublicKey(generateReferenceKeyPair(curve).ecPoint, curve);

        assertEquals("EC", publicKey.getAlgorithm(),
                "KeyFactory algorithm name must be the portable 'EC', not the BouncyCastle-only 'ECDSA' alias");
    }

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void getPrivateKeyReportsThePortableAlgorithmName(ECDSACurve curve) throws GeneralSecurityException {
        PrivateKey privateKey = ECDSAKeyFactory.getPrivateKey(generateReferenceKeyPair(curve).scalar, curve);

        assertEquals("EC", privateKey.getAlgorithm(),
                "KeyFactory algorithm name must be the portable 'EC', not the BouncyCastle-only 'ECDSA' alias");
    }

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void getPublicKeyIsUsableWithThePlatformsNativeEcProvider(ECDSACurve curve) throws GeneralSecurityException {
        assumeNativeEcProviderAvailable();
        ReferenceKeyPair reference = generateReferenceKeyPair(curve);

        PublicKey rebuiltPublicKey = ECDSAKeyFactory.getPublicKey(reference.ecPoint, curve);

        Signature signature = Signature.getInstance(signatureAlgorithmFor(curve), NATIVE_EC_PROVIDER);
        assertDoesNotThrow(() -> signature.initVerify(rebuiltPublicKey),
                "Public key built for " + curve + " must be usable with the platform's native EC provider");
    }

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void getPrivateKeyIsUsableWithThePlatformsNativeEcProvider(ECDSACurve curve) throws GeneralSecurityException {
        assumeNativeEcProviderAvailable();
        ReferenceKeyPair reference = generateReferenceKeyPair(curve);

        PrivateKey rebuiltPrivateKey = ECDSAKeyFactory.getPrivateKey(reference.scalar, curve);

        Signature signature = Signature.getInstance(signatureAlgorithmFor(curve), NATIVE_EC_PROVIDER);
        assertDoesNotThrow(() -> signature.initSign(rebuiltPrivateKey),
                "Private key built for " + curve + " must be usable with the platform's native EC provider");
    }

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void signatureMadeWithRebuiltPrivateKeyVerifiesAgainstOriginalPublicKey(ECDSACurve curve) throws GeneralSecurityException {
        assumeNativeEcProviderAvailable();
        ReferenceKeyPair reference = generateReferenceKeyPair(curve);
        byte[] message = "issue-1018".getBytes();

        PrivateKey rebuiltPrivateKey = ECDSAKeyFactory.getPrivateKey(reference.scalar, curve);
        Signature signer = Signature.getInstance(signatureAlgorithmFor(curve), NATIVE_EC_PROVIDER);
        signer.initSign(rebuiltPrivateKey);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(signatureAlgorithmFor(curve), NATIVE_EC_PROVIDER);
        verifier.initVerify(reference.keyPair.getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(sig), "Signature made with rebuilt private key must verify against the original public key");
    }

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void signatureMadeWithOriginalPrivateKeyVerifiesAgainstRebuiltPublicKey(ECDSACurve curve) throws GeneralSecurityException {
        assumeNativeEcProviderAvailable();
        ReferenceKeyPair reference = generateReferenceKeyPair(curve);
        byte[] message = "issue-1018".getBytes();

        Signature signer = Signature.getInstance(signatureAlgorithmFor(curve), NATIVE_EC_PROVIDER);
        signer.initSign(reference.keyPair.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        PublicKey rebuiltPublicKey = ECDSAKeyFactory.getPublicKey(reference.ecPoint, curve);
        Signature verifier = Signature.getInstance(signatureAlgorithmFor(curve), NATIVE_EC_PROVIDER);
        verifier.initVerify(rebuiltPublicKey);
        verifier.update(message);
        assertTrue(verifier.verify(sig), "Signature made with the original private key must verify against the rebuilt public key");
    }

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void getPublicKeyPreservesThePoint(ECDSACurve curve) throws GeneralSecurityException {
        ReferenceKeyPair reference = generateReferenceKeyPair(curve);

        ECPublicKey rebuiltPublicKey = (ECPublicKey) ECDSAKeyFactory.getPublicKey(reference.ecPoint, curve);

        assertEquals(reference.ecPoint, rebuiltPublicKey.getW());
    }

    @ParameterizedTest
    @EnumSource(ECDSACurve.class)
    public void getPrivateKeyPreservesTheScalar(ECDSACurve curve) throws GeneralSecurityException {
        ReferenceKeyPair reference = generateReferenceKeyPair(curve);

        ECPrivateKey rebuiltPrivateKey = (ECPrivateKey) ECDSAKeyFactory.getPrivateKey(reference.scalar, curve);

        assertEquals(reference.scalar, rebuiltPrivateKey.getS());
    }

    @Test
    public void getPublicKeyRejectsNullPoint() {
        assertThrows(NullPointerException.class, () -> ECDSAKeyFactory.getPublicKey(null, ECDSACurve.SECP256R1));
    }

    @Test
    public void getPublicKeyRejectsNullCurve() throws GeneralSecurityException {
        ECPoint point = generateReferenceKeyPair(ECDSACurve.SECP256R1).ecPoint;
        assertThrows(NullPointerException.class, () -> ECDSAKeyFactory.getPublicKey(point, null));
    }

    @Test
    public void getPrivateKeyRejectsNullScalar() {
        assertThrows(NullPointerException.class, () -> ECDSAKeyFactory.getPrivateKey(null, ECDSACurve.SECP256R1));
    }

    @Test
    public void getPrivateKeyRejectsNullCurve() {
        assertThrows(NullPointerException.class,
                () -> ECDSAKeyFactory.getPrivateKey(java.math.BigInteger.ONE, null));
    }

    private static void assumeNativeEcProviderAvailable() {
        assumeTrue(Security.getProvider(NATIVE_EC_PROVIDER) != null,
                "Test requires the '" + NATIVE_EC_PROVIDER + "' JCA provider to be available");
    }

    private ReferenceKeyPair generateReferenceKeyPair(ECDSACurve curve) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec(curve.getCurveName()));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPoint point = ((ECPublicKey) keyPair.getPublic()).getW();
        java.math.BigInteger scalar = ((ECPrivateKey) keyPair.getPrivate()).getS();
        return new ReferenceKeyPair(keyPair, point, scalar);
    }

    private static String signatureAlgorithmFor(ECDSACurve curve) {
        switch (curve) {
            case SECP256R1:
                return "SHA256withECDSA";
            case SECP384R1:
                return "SHA384withECDSA";
            case SECP521R1:
                return "SHA512withECDSA";
            default:
                throw new IllegalArgumentException("Unsupported curve: " + curve);
        }
    }

    private static final class ReferenceKeyPair {
        private final KeyPair keyPair;
        private final ECPoint ecPoint;
        private final java.math.BigInteger scalar;

        private ReferenceKeyPair(KeyPair keyPair, ECPoint ecPoint, java.math.BigInteger scalar) {
            this.keyPair = keyPair;
            this.ecPoint = ecPoint;
            this.scalar = scalar;
        }
    }
}
