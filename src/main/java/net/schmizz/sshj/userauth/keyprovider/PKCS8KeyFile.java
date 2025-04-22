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
package net.schmizz.sshj.userauth.keyprovider;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.encodingrules.der.DERDecoder;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.asn1.types.string.ASN1BitString;
import com.hierynomus.asn1.types.string.ASN1OctetString;
import com.hierynomus.sshj.common.KeyAlgorithm;
import com.hierynomus.sshj.common.KeyDecryptionFailedException;
import net.schmizz.sshj.common.ECDSACurve;
import net.schmizz.sshj.common.ECDSAKeyFactory;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.keyprovider.PEMKey.PEMKeyType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECField;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Key File implementation supporting PEM-encoded PKCS8 and PKCS1 formats with or without password-based encryption
 */
public class PKCS8KeyFile extends BaseFileKeyProvider {
    /** Bouncy Castle class for detecting support of historical OpenSSL password-based decryption */
    private static final String BOUNCY_CASTLE_CLASS = "org.bouncycastle.openssl.PEMDecryptor";

    private static final boolean HISTORICAL_DECRYPTION_SUPPORTED = isHistoricalDecryptionSupported();

    protected final Logger log = LoggerFactory.getLogger(getClass());

    public static class Factory implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new PKCS8KeyFile();
        }

        @Override
        public String getName() {
            return "PKCS8";
        }
    }

    @Override
    protected KeyPair readKeyPair() throws IOException {
        final PEMKeyReader pemKeyReader;

        if (HISTORICAL_DECRYPTION_SUPPORTED) {
            if (pwdf == null) {
                pemKeyReader = new StandardPEMKeyReader();
            } else {
                pemKeyReader = new EncryptedPEMKeyReader(pwdf, resource);
            }
        } else {
            pemKeyReader = new StandardPEMKeyReader();
        }

        try (BufferedReader bufferedReader = new BufferedReader(resource.getReader())) {
            final PEMKey pemKey = pemKeyReader.readPemKey(bufferedReader);
            return readKeyPair(pemKey);
        }
    }

    private KeyPair readKeyPair(final PEMKey pemKey) throws IOException {
        final KeyPair keyPair;

        final PEMKeyType pemKeyType = pemKey.getPemKeyType();
        final byte[] pemKeyBody = pemKey.getBody();

        if (PEMKeyType.DSA == pemKeyType) {
            keyPair = readDsaKeyPair(pemKeyBody);
        } else if (PEMKeyType.EC == pemKeyType) {
            keyPair = readEcKeyPair(pemKeyBody);
        } else if (PEMKeyType.PKCS8 == pemKeyType) {
            keyPair = getPkcs8KeyPair(pemKeyBody);
        } else if (PEMKeyType.PKCS8_ENCRYPTED == pemKeyType) {
            keyPair = readEncryptedPkcs8KeyPair(pemKeyBody);
        } else if (PEMKeyType.RSA == pemKeyType) {
            keyPair = readRsaKeyPair(pemKeyBody);
        } else {
            throw new IOException(String.format("PEM Key Type [%s] not supported", pemKeyType));
        }

        return keyPair;
    }

    @Override
    public String toString() {
        return "PKCS8KeyFile{resource=" + resource + "}";
    }

    private KeyPair readDsaKeyPair(final byte[] pemKeyBody) throws IOException {
        try (ASN1InputStream inputStream = new ASN1InputStream(new DERDecoder(), pemKeyBody)) {
            final ASN1Sequence sequence = inputStream.readObject();

            final BigInteger p = getBigInteger(sequence, 1);
            final BigInteger q = getBigInteger(sequence, 2);
            final BigInteger g = getBigInteger(sequence, 3);

            final BigInteger y = getBigInteger(sequence, 4);
            final BigInteger x = getBigInteger(sequence, 5);

            final DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(x, p, q, g);
            final DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);

            final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyAlgorithm.DSA);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            return new KeyPair(publicKey, privateKey);
        } catch (final Exception e) {
            throw new IOException("PEM Key [DSA] processing failed", e);
        }
    }

    private KeyPair readRsaKeyPair(final byte[] pemKeyBody) throws IOException {
        try (ASN1InputStream inputStream = new ASN1InputStream(new DERDecoder(), pemKeyBody)) {
            final ASN1Sequence sequence = inputStream.readObject();
            final BigInteger modulus = getBigInteger(sequence, 1);
            final BigInteger publicExponent = getBigInteger(sequence, 2);
            final BigInteger privateExponent = getBigInteger(sequence, 3);
            final BigInteger prime1 = getBigInteger(sequence, 4);
            final BigInteger prime2 = getBigInteger(sequence, 5);
            final BigInteger exponent1 = getBigInteger(sequence, 6);
            final BigInteger exponent2 = getBigInteger(sequence, 7);
            final BigInteger coefficient = getBigInteger(sequence, 8);

            final RSAPrivateCrtKeySpec privateKeySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient);
            final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyAlgorithm.RSA);
            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            return new KeyPair(publicKey, privateKey);
        } catch (final Exception e) {
            throw new IOException("PEM Key [RSA] processing failed", e);
        }
    }

    private KeyPair readEcKeyPair(final byte[] pemKeyBody) throws IOException {
        try (ASN1InputStream inputStream = new ASN1InputStream(new DERDecoder(), pemKeyBody)) {
            final ASN1Sequence sequence = inputStream.readObject();

            final ASN1TaggedObject taggedObjectParameters = (ASN1TaggedObject) sequence.get(2);
            final ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) taggedObjectParameters.getObject();
            final String objectId = objectIdentifier.getValue();
            final ECNamedCurveObjectIdentifier ecNamedCurveObjectIdentifier = getEcNamedCurve(objectId);

            final ASN1OctetString privateKeyOctetString = (ASN1OctetString) sequence.get(1);
            final BigInteger privateKeyInteger = new BigInteger(1, privateKeyOctetString.getValue());
            final ECPrivateKey privateKey = (ECPrivateKey) ECDSAKeyFactory.getPrivateKey(privateKeyInteger, ecNamedCurveObjectIdentifier.ecdsaCurve);
            final ECParameterSpec ecParameterSpec = privateKey.getParams();

            final ASN1TaggedObject taggedBitString = (ASN1TaggedObject) sequence.get(3);
            final ASN1BitString publicKeyBitString = (ASN1BitString) taggedBitString.getObject();
            final byte[] bitString = publicKeyBitString.getValueBytes();
            final PublicKey publicKey = getEcPublicKey(bitString, ecParameterSpec);
            return new KeyPair(publicKey, privateKey);
        } catch (final Exception e) {
            throw new IOException("PEM Key [EC] processing failed", e);
        }
    }

    private ECNamedCurveObjectIdentifier getEcNamedCurve(final String objectId) {
        ECNamedCurveObjectIdentifier objectIdentifierFound = null;

        for (final ECNamedCurveObjectIdentifier objectIdentifier : ECNamedCurveObjectIdentifier.values()) {
            if (objectIdentifier.objectId.equals(objectId)) {
                objectIdentifierFound = objectIdentifier;
            }
        }

        if (objectIdentifierFound == null) {
            throw new IllegalArgumentException(String.format("ECDSA Key Algorithm [%s] not supported", objectId));
        }

        return objectIdentifierFound;
    }

    private KeyPair readEncryptedPkcs8KeyPair(final byte[] pemKeyBody) throws IOException {
        if (pwdf == null) {
            throw new KeyDecryptionFailedException("Password not provided for encrypted PKCS8 key");
        }

        KeyPair keyPair = null;
        try {
            char[] password = pwdf.reqPassword(resource);
            while (password != null) {
                try {
                    final PKCS8EncodedKeySpec encodedKeySpec = getPkcs8DecryptedKeySpec(password, pemKeyBody);
                    keyPair = getPkcs8KeyPair(encodedKeySpec.getEncoded());
                    break;
                } catch (final KeyDecryptionFailedException e) {
                    if (pwdf.shouldRetry(resource)) {
                        password = pwdf.reqPassword(resource);
                    } else {
                        throw e;
                    }
                }
            }
        } catch (final GeneralSecurityException e) {
            throw new IOException("PEM Key [PKCS8] processing failed", e);
        }

        if (keyPair == null) {
            throw new KeyDecryptionFailedException("PEM Key [PKCS8] decryption failed");
        }

        return keyPair;
    }

    private PKCS8EncodedKeySpec getPkcs8DecryptedKeySpec(final char[] password, final byte[] encoded) throws IOException, GeneralSecurityException {
        try {
            final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encoded);
            final AlgorithmParameters algorithmParameters = encryptedPrivateKeyInfo.getAlgParameters();
            final String secretKeyAlgorithm = algorithmParameters.toString();
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
            final PBEKeySpec secretKeySpec = new PBEKeySpec(password);
            final SecretKey secretKey = secretKeyFactory.generateSecret(secretKeySpec);
            final Cipher cipher = Cipher.getInstance(secretKeyAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameters);

            try {
                return encryptedPrivateKeyInfo.getKeySpec(cipher);
            } catch (final GeneralSecurityException e) {
                throw new KeyDecryptionFailedException(String.format("PKCS8 Key Decryption failed for algorithm [%s]", secretKeyAlgorithm), e);
            }
        } finally {
            PasswordUtils.blankOut(password);
        }
    }

    private KeyPair getPkcs8KeyPair(final byte[] encoded) throws IOException {
        try (ASN1InputStream inputStream = new ASN1InputStream(new DERDecoder(), encoded)) {
            final ASN1Sequence sequence = inputStream.readObject();

            final ASN1Sequence privateKeyAlgorithmSequence =  (ASN1Sequence) sequence.get(1);
            final ASN1ObjectIdentifier privateKeyAlgorithm = (ASN1ObjectIdentifier) privateKeyAlgorithmSequence.get(0);
            final String privateKeyAlgorithmObjectId = privateKeyAlgorithm.getValue();
            final KeyAlgorithmObjectIdentifier keyAlgorithmObjectIdentifier = getKeyAlgorithmObjectIdentifier(privateKeyAlgorithmObjectId);

            return getPkcs8KeyPair(keyAlgorithmObjectIdentifier, encoded);
        } catch (final Exception e) {
            throw new IOException("PEM Key [PKCS8] processing failed", e);
        }
    }

    private KeyPair getPkcs8KeyPair(final KeyAlgorithmObjectIdentifier objectIdentifier, final byte[] privateKeyInfo) throws GeneralSecurityException {
        final PublicKey publicKey;

        final PrivateKey privateKey = getPkcs8PrivateKey(objectIdentifier, privateKeyInfo);

        if (privateKey instanceof RSAPrivateCrtKey) {
            final RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
            final BigInteger modulus = rsaPrivateKey.getModulus();
            final BigInteger publicExponent = rsaPrivateKey.getPublicExponent();
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            final KeyFactory keyFactory = SecurityUtils.getKeyFactory(privateKey.getAlgorithm());
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } else if (privateKey instanceof DSAPrivateKey) {
            final DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privateKey;
            final DSAParams dsaParams = dsaPrivateKey.getParams();
            final BigInteger p = dsaParams.getP();
            final BigInteger g = dsaParams.getG();
            final BigInteger q = dsaParams.getQ();
            final BigInteger x = dsaPrivateKey.getX();
            final BigInteger y = g.modPow(x, p);
            final DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
            final KeyFactory keyFactory = SecurityUtils.getKeyFactory(privateKey.getAlgorithm());
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } else if (privateKey instanceof ECPrivateKey) {
            final ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
            final ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();

            // Read ECDSA Public Key from ASN.1
            try (ASN1InputStream inputStream = new ASN1InputStream(new DERDecoder(), privateKeyInfo)) {
                final ASN1Sequence sequence = inputStream.readObject();
                final ASN1OctetString keyOctetString = (ASN1OctetString) sequence.get(2);
                final byte[] keyBytes = keyOctetString.getValue();
                try (ASN1InputStream keyInputStream = new ASN1InputStream(new DERDecoder(), keyBytes)) {
                    final ASN1Sequence keySequence = keyInputStream.readObject();
                    final ASN1TaggedObject taggedObject = (ASN1TaggedObject) keySequence.get(2);
                    final ASN1BitString publicKeyBitString = taggedObject.getObject(ASN1Tag.BIT_STRING);
                    final byte[] bitString = publicKeyBitString.getValueBytes();

                    publicKey = getEcPublicKey(bitString, ecParameterSpec);
                }
            } catch (final IOException e) {
                throw new GeneralSecurityException("ECDSA Private Key Info parsing failed", e);
            }
        } else {
            throw new GeneralSecurityException(String.format("PEM Key [PKCS8] algorithm [%s] Key Pair derivation not supported", privateKey.getAlgorithm()));
        }

        return new KeyPair(publicKey, privateKey);
    }

    private PrivateKey getPkcs8PrivateKey(final KeyAlgorithmObjectIdentifier objectIdentifier, final byte[] privateKeyInfo) throws GeneralSecurityException {
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyInfo);
        final KeyFactory keyFactory = SecurityUtils.getKeyFactory(objectIdentifier.name());
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey getEcPublicKey(final byte[] bitString, final ECParameterSpec ecParameterSpec) throws GeneralSecurityException {
        final EllipticCurve ellipticCurve = ecParameterSpec.getCurve();
        final ECField ecField = ellipticCurve.getField();
        final int fieldSize = (ecField.getFieldSize() + 7) / 8;
        final int publicKeyPointSize = fieldSize * 2;

        final byte[] x = new byte[fieldSize];
        final byte[] y = new byte[fieldSize];

        final int pointOffset = bitString.length - publicKeyPointSize;

        System.arraycopy(bitString, pointOffset, x, 0, x.length);
        System.arraycopy(bitString, pointOffset + y.length, y, 0, y.length);

        final BigInteger pointX = new BigInteger(1, x);
        final BigInteger pointY = new BigInteger(1, y);
        final ECPoint point = new ECPoint(pointX, pointY);
        final ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, ecParameterSpec);

        final KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyAlgorithm.EC_KEYSTORE);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private KeyAlgorithmObjectIdentifier getKeyAlgorithmObjectIdentifier(final String objectId) {
        KeyAlgorithmObjectIdentifier keyAlgorithmObjectIdentifier = null;

        for (final KeyAlgorithmObjectIdentifier objectIdentifier : KeyAlgorithmObjectIdentifier.values()) {
            if (objectIdentifier.getObjectId().equals(objectId)) {
                keyAlgorithmObjectIdentifier = objectIdentifier;
            }
        }

        if (keyAlgorithmObjectIdentifier == null) {
            throw new IllegalArgumentException(String.format("PKCS8 Private Key Algorithm [%s] not supported", objectId));
        }

        return keyAlgorithmObjectIdentifier;
    }

    private BigInteger getBigInteger(final ASN1Sequence sequence, final int index) {
        final ASN1Integer integer = (ASN1Integer) sequence.get(index);
        return integer.getValue();
    }

    private static boolean isHistoricalDecryptionSupported() {
        try {
            // Support requires Bouncy Castle library for OpenSSL password-based decryption
            Class.forName(BOUNCY_CASTLE_CLASS);
            return true;
        } catch (final Exception e) {
            return false;
        }
    }

    private enum ECNamedCurveObjectIdentifier {
        SECP256R1("1.2.840.10045.3.1.7", ECDSACurve.SECP256R1),

        SECP384R1("1.3.132.0.34", ECDSACurve.SECP384R1),

        SECP521R1("1.3.132.0.35", ECDSACurve.SECP521R1);

        private final String objectId;

        private final ECDSACurve ecdsaCurve;

        ECNamedCurveObjectIdentifier(final String objectId, final ECDSACurve ecdsaCurve) {
            this.objectId = objectId;
            this.ecdsaCurve = ecdsaCurve;
        }
    }

    private enum KeyAlgorithmObjectIdentifier {
        DSA("1.2.840.10040.4.1"),

        EC("1.2.840.10045.2.1"),

        RSA("1.2.840.113549.1.1.1");

        private final String objectId;

        KeyAlgorithmObjectIdentifier(final String objectId) {
            this.objectId = objectId;
        }

        String getObjectId() {
            return objectId;
        }
    }
}
