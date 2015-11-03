/**
 * Copyright 2009 sshj contributors
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

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/** Type of key e.g. rsa, dsa */
public enum KeyType {


    /** SSH identifier for RSA keys */
    RSA("ssh-rsa") {
        @Override
        public PublicKey readPubKeyFromBuffer(String type, Buffer<?> buf)
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
        public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
            final RSAPublicKey rsaKey = (RSAPublicKey) pk;
            buf.putString(sType)
                    .putMPInt(rsaKey.getPublicExponent()) // e
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
        public PublicKey readPubKeyFromBuffer(String type, Buffer<?> buf)
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
        public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
            final DSAPublicKey dsaKey = (DSAPublicKey) pk;
            buf.putString(sType)
                    .putMPInt(dsaKey.getParams().getP()) // p
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
        public PublicKey readPubKeyFromBuffer(String type, Buffer<?> buf)
                throws GeneralSecurityException {
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
                            type,
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
        public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
            final ECPublicKey ecdsa = (ECPublicKey) pk;
            final java.security.spec.ECPoint point = ecdsa.getW();
            final byte[] x = trimStartingZeros(point.getAffineX().toByteArray());
            final byte[] y = trimStartingZeros(point.getAffineY().toByteArray());

            buf.putString(sType)
                .putString(NISTP_CURVE)
                .putUInt32(1 + x.length + y.length)
                .putRawBytes(new byte[] { (byte) 0x04 })
                .putRawBytes(x)
                .putRawBytes(y)
            ;
        }

        @Override
        protected boolean isMyType(Key key) {
            return ("ECDSA".equals(key.getAlgorithm()));
        }

        private byte[] trimStartingZeros(byte[] in) {

            int i = 0;
            for (; i < in.length; i++) {
                if (in[i] != 0) {
                    break;
                }
            }
            final byte[] out = new byte[in.length - i];
            System.arraycopy(in, i, out, 0, out.length);
            return out;
        }
    },

    /** Unrecognized */
    UNKNOWN("unknown") {
        @Override
        public PublicKey readPubKeyFromBuffer(String type, Buffer<?> buf)
                throws GeneralSecurityException {
            throw new UnsupportedOperationException("Don't know how to decode key:" + type);
        }

        @Override
        public void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf) {
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

    public abstract PublicKey readPubKeyFromBuffer(String type, Buffer<?> buf)
            throws GeneralSecurityException;

    public abstract void putPubKeyIntoBuffer(PublicKey pk, Buffer<?> buf);

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

}
