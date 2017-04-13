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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.sshj.secg.SecgUtils;
import com.hierynomus.sshj.signature.Ed25519PublicKey;
import com.hierynomus.sshj.userauth.certificate.Certificate;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.schmizz.sshj.common.Buffer.BufferException;

/** Type of key e.g. rsa, dsa */
public enum KeyType {

    /** SSH identifier for RSA keys */
    RSA("ssh-rsa") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            final BigInteger e, n;
            try {
                e = buf.readMPInt();
                n = buf.readMPInt();
            } catch (Buffer.BufferException be) {
                throw new GeneralSecurityException(be);
            }
            final KeyFactory keyFactory = SecurityUtils.getKeyFactory("RSA");
            return keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            final RSAPublicKey rsaKey = (RSAPublicKey) pk;
            buf.putMPInt(rsaKey.getPublicExponent()) // e
                .putMPInt(rsaKey.getModulus()); // n
        }

        @Override
        protected boolean isMyType(Key key) {
            return (key instanceof RSAPublicKey || key instanceof RSAPrivateKey);
        }
    },

    /** SSH identifier for DSA keys */
    DSA("ssh-dss") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            BigInteger p, q, g, y;
            try {
                p = buf.readMPInt();
                q = buf.readMPInt();
                g = buf.readMPInt();
                y = buf.readMPInt();
            } catch (Buffer.BufferException be) {
                throw new GeneralSecurityException(be);
            }
            final KeyFactory keyFactory = SecurityUtils.getKeyFactory("DSA");
            return keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            final DSAPublicKey dsaKey = (DSAPublicKey) pk;
            buf.putMPInt(dsaKey.getParams().getP()) // p
                    .putMPInt(dsaKey.getParams().getQ()) // q
                    .putMPInt(dsaKey.getParams().getG()) // g
                    .putMPInt(dsaKey.getY()); // y
        }

        @Override
        protected boolean isMyType(Key key) {
            return (key instanceof DSAPublicKey || key instanceof DSAPrivateKey);
        }

    },

    /** SSH identifier for ECDSA keys */
    ECDSA("ecdsa-sha2-nistp256") {
        private final Logger log = LoggerFactory.getLogger(getClass());

        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            if (!SecurityUtils.isBouncyCastleRegistered()) {
                throw new GeneralSecurityException("BouncyCastle is required to read a key of type " + sType);
            }
            try {
                // final String algo = buf.readString();  it has been already read
                final String curveName = buf.readString();
                final int keyLen = buf.readUInt32AsInt();
                final byte x04 = buf.readByte();  // it must be 0x04, but don't think we need that check
                final byte[] x = new byte[(keyLen - 1) / 2];
                final byte[] y = new byte[(keyLen - 1) / 2];
                buf.readRawBytes(x);
                buf.readRawBytes(y);
                if(log.isDebugEnabled()) {
                    log.debug(String.format("Key algo: %s, Key curve: %s, Key Len: %s, 0x04: %s\nx: %s\ny: %s",
                            sType,
                            curveName,
                            keyLen,
                            x04,
                            Arrays.toString(x),
                            Arrays.toString(y))
                    );
                }

                if (!NISTP_CURVE.equals(curveName)) {
                    throw new GeneralSecurityException(String.format("Unknown curve %s", curveName));
                }

                BigInteger bigX = new BigInteger(1, x);
                BigInteger bigY = new BigInteger(1, y);

                X9ECParameters ecParams = NISTNamedCurves.getByName("p-256");
                ECPoint pPublicPoint = ecParams.getCurve().createPoint(bigX, bigY);
                ECParameterSpec spec = new ECParameterSpec(ecParams.getCurve(),
                        ecParams.getG(), ecParams.getN());
                ECPublicKeySpec publicSpec = new ECPublicKeySpec(pPublicPoint, spec);

                KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
                return keyFactory.generatePublic(publicSpec);
            } catch (Exception ex) {
                throw new GeneralSecurityException(ex);
            }
        }


        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            final ECPublicKey ecdsa = (ECPublicKey) pk;
            byte[] encoded = SecgUtils.getEncoded(ecdsa.getW(), ecdsa.getParams().getCurve());

            buf.putString(NISTP_CURVE)
                .putBytes(encoded);
        }

        @Override
        protected boolean isMyType(Key key) {
            return ("ECDSA".equals(key.getAlgorithm()));
        }
    },

    ED25519("ssh-ed25519") {
        private final Logger log = LoggerFactory.getLogger(KeyType.class);
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf) throws GeneralSecurityException {
            try {
                final int keyLen = buf.readUInt32AsInt();
                final byte[] p = new byte[keyLen];
                buf.readRawBytes(p);
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Key algo: %s, Key curve: 25519, Key Len: %s\np: %s",
                            sType,
                            keyLen,
                            Arrays.toString(p))
                    );
                }

                EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
                EdDSAPublicKeySpec publicSpec = new EdDSAPublicKeySpec(p, ed25519);
                return new Ed25519PublicKey(publicSpec);

            } catch (Buffer.BufferException be) {
                throw new SSHRuntimeException(be);
            }
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            EdDSAPublicKey key = (EdDSAPublicKey) pk;
            buf.putBytes(key.getAbyte());
        }

        @Override
        protected boolean isMyType(Key key) {
            return "EdDSA".equals(key.getAlgorithm());
        }
    },

    /** Signed rsa certificate */
    RSA_CERT("ssh-rsa-cert-v01@openssh.com") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            return CertUtils.readPubKey(buf, RSA);
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            CertUtils.writePubKeyContentsIntoBuffer(pk, RSA, buf);
        }

        @Override
        protected boolean isMyType(Key key) {
            return CertUtils.isCertificateOfType(key, RSA);
        }
    },

    /** Signed dsa certificate */
    DSA_CERT("ssh-dss-cert-v01@openssh.com") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            return CertUtils.readPubKey(buf, DSA);
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            CertUtils.writePubKeyContentsIntoBuffer(pk, DSA, buf);
        }

        @Override
        protected boolean isMyType(Key key) {
            return CertUtils.isCertificateOfType(key, DSA);
        }
    },

    /** Unrecognized */
    UNKNOWN("unknown") {
        @Override
        public PublicKey readPubKeyFromBuffer(Buffer<?> buf)
                throws GeneralSecurityException {
            throw new UnsupportedOperationException("Don't know how to decode key:" + sType);
        }

        @Override
        public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
            throw new UnsupportedOperationException("Don't know how to encode key: " + pk);
        }

        @Override
        protected void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
            throw new UnsupportedOperationException("Don't know how to encode key: " + pk);
        }

        @Override
        protected boolean isMyType(Key key) {
            return false;
        }
    };


    private static final String NISTP_CURVE = "nistp256";

    protected final String sType;

    private KeyType(String type) {
        this.sType = type;
    }

    public abstract PublicKey readPubKeyFromBuffer(Buffer<?> buf)
            throws GeneralSecurityException;

    protected abstract void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf);

    public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
        writePubKeyContentsIntoBuffer(pk, buf.putString(sType));
    }

    protected abstract boolean isMyType(Key key);

    public static KeyType fromKey(Key key) {
        for (KeyType kt : values())
            if (kt.isMyType((key)))
                return kt;
        return UNKNOWN;
    }

    public static KeyType fromString(String sType) {
        for (KeyType kt : values())
            if (kt.sType.equals(sType))
                return kt;
        return UNKNOWN;
    }

    @Override
    public String toString() {
        return sType;
    }

    static class CertUtils {

        @SuppressWarnings("unchecked")
        static <T extends PublicKey> Certificate<T> readPubKey(Buffer<?> buf, KeyType innerKeyType) throws GeneralSecurityException {
            Certificate.Builder<T> builder = Certificate.getBuilder();

            try {
                builder.nonce(buf.readBytes());
                builder.publicKey((T) innerKeyType.readPubKeyFromBuffer(buf));
                builder.serial(buf.readUInt64AsBigInteger());
                builder.type(buf.readUInt32());
                builder.id(buf.readString());
                builder.validPrincipals(unpackList(buf.readBytes()));
                builder.validAfter(dateFromEpoch(buf.readUInt64()));
                builder.validBefore(dateFromEpoch(buf.readUInt64()));
                builder.critOptions(unpackMap(buf.readBytes()));
                builder.extensions(unpackMap(buf.readBytes()));
                buf.readString(); // reserved
                builder.signatureKey(buf.readBytes());
                builder.signature(buf.readBytes());
            } catch (Buffer.BufferException be) {
                throw new GeneralSecurityException(be);
            }

            return builder.build();
        }

        static void writePubKeyContentsIntoBuffer(PublicKey publicKey, KeyType innerKeyType, Buffer<?> buf) {
            Certificate<PublicKey> certificate = toCertificate(publicKey);
            buf.putBytes(certificate.getNonce());
            innerKeyType.writePubKeyContentsIntoBuffer(certificate.getKey(), buf);
            buf.putUInt64(certificate.getSerial())
                .putUInt32(certificate.getType())
                .putString(certificate.getId())
                .putBytes(packList(certificate.getValidPrincipals()))
                .putUInt64(epochFromDate(certificate.getValidAfter()))
                .putUInt64(epochFromDate(certificate.getValidBefore()))
                .putBytes(packMap(certificate.getCritOptions()))
                .putBytes(packMap(certificate.getExtensions()))
                .putString("") // reserved
                .putBytes(certificate.getSignatureKey())
                .putBytes(certificate.getSignature());
        }

        static boolean isCertificateOfType(Key key, KeyType innerKeyType) {
            if (!(key instanceof Certificate)) {
                return false;
            }
            @SuppressWarnings("unchecked")
            Key innerKey = ((Certificate<PublicKey>) key).getKey();
            return innerKeyType.isMyType(innerKey);
        }

        @SuppressWarnings("unchecked")
        static Certificate<PublicKey> toCertificate(PublicKey key) {
            if (!(key instanceof Certificate)) {
                throw new UnsupportedOperationException("Can't convert non-certificate key " +
                                                        key.getAlgorithm() + " to certificate");
            }
            return ((Certificate<PublicKey>) key);
        }

        private static Date dateFromEpoch(long seconds) {
            return new Date(seconds * 1000);
        }

        private static long epochFromDate(Date date) {
            return date.getTime() / 1000;
        }

        private static String unpackString(byte[] packedString) throws BufferException {
            if (packedString.length == 0) {
                return "";
            }
            return new Buffer.PlainBuffer(packedString).readString();
        }

        private static List<String> unpackList(byte[] packedString) throws BufferException {
            List<String> list = new ArrayList<String>();
            Buffer<?> buf = new Buffer.PlainBuffer(packedString);
            while (buf.available() > 0) {
                list.add(buf.readString());
            }
            return list;
        }

        private static Map<String, String> unpackMap(byte[] packedString) throws BufferException {
            Map<String, String> map = new LinkedHashMap<String, String>();
            Buffer<?> buf = new Buffer.PlainBuffer(packedString);
            while (buf.available() > 0) {
                String name = buf.readString();
                String data = unpackString(buf.readStringAsBytes());
                map.put(name, data);
            }
            return map;
        }

        private static byte[] packString(String data) {
            if (data == null || data.isEmpty()) {
                return "".getBytes();
            }
            return new Buffer.PlainBuffer().putString(data).getCompactData();
        }

        private static byte[] packList(Iterable<String> strings) {
            Buffer<?> buf = new Buffer.PlainBuffer();
            for (String string : strings) {
                buf.putString(string);
            }
            return buf.getCompactData();
        }

        private static byte[] packMap(Map<String, String> map) {
            Buffer<?> buf = new Buffer.PlainBuffer();
            List<String> keys = new ArrayList<String>(map.keySet());
            Collections.sort(keys);
            for (String key : keys) {
                buf.putString(key);
                String value = map.get(key);
                buf.putString(packString(value));
            }
            return buf.getCompactData();
        }
    }
}
