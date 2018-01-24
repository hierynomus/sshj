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

import com.hierynomus.sshj.secg.SecgUtils;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

class ECDSAVariationsAdapter {

    private final static String BASE_ALGORITHM_NAME = "ecdsa-sha2-nistp";

    private final static Logger log = LoggerFactory.getLogger(ECDSAVariationsAdapter.class);

    public final static Map<String, String> SUPPORTED_CURVES = new HashMap<String, String>();
    public final static Map<String, String> NIST_CURVES_NAMES = new HashMap<String, String>();

    static {
        NIST_CURVES_NAMES.put("256", "p-256");
        NIST_CURVES_NAMES.put("384", "p-384");
        NIST_CURVES_NAMES.put("521", "p-521");

        SUPPORTED_CURVES.put("256", "nistp256");
        SUPPORTED_CURVES.put("384", "nistp384");
        SUPPORTED_CURVES.put("521", "nistp521");
    }

    static PublicKey readPubKeyFromBuffer(Buffer<?> buf, String variation) throws GeneralSecurityException {
        String algorithm = BASE_ALGORITHM_NAME + variation;
        if (!SecurityUtils.isBouncyCastleRegistered()) {
            throw new GeneralSecurityException("BouncyCastle is required to read a key of type " + algorithm);
        }
        try {
            // final String algo = buf.readString(); it has been already read
            final String curveName = buf.readString();
            final int keyLen = buf.readUInt32AsInt();
            final byte x04 = buf.readByte(); // it must be 0x04, but don't think
            // we need that check
            final byte[] x = new byte[(keyLen - 1) / 2];
            final byte[] y = new byte[(keyLen - 1) / 2];
            buf.readRawBytes(x);
            buf.readRawBytes(y);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Key algo: %s, Key curve: %s, Key Len: %s, 0x04: %s\nx: %s\ny: %s", 
                        algorithm, curveName, keyLen, x04, Arrays.toString(x), Arrays.toString(y)));
            }

            if (!SUPPORTED_CURVES.values().contains(curveName)) {
                throw new GeneralSecurityException(String.format("Unknown curve %s", curveName));
            }

            BigInteger bigX = new BigInteger(1, x);
            BigInteger bigY = new BigInteger(1, y);

            String name = NIST_CURVES_NAMES.get(variation);
            X9ECParameters ecParams = NISTNamedCurves.getByName(name);
            ECNamedCurveSpec ecCurveSpec = new ECNamedCurveSpec(name, ecParams.getCurve(), ecParams.getG(), ecParams.getN());
            ECPoint p = new ECPoint(bigX, bigY);
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(p, ecCurveSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception ex) {
            throw new GeneralSecurityException(ex);
        }
    }

    static void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
        final ECPublicKey ecdsa = (ECPublicKey) pk;
        byte[] encoded = SecgUtils.getEncoded(ecdsa.getW(), ecdsa.getParams().getCurve());

        buf.putString("nistp" + Integer.toString(fieldSizeFromKey(ecdsa)))
            .putBytes(encoded);
    }

    static boolean isECKeyWithFieldSize(Key key, int fieldSize) {
        return "ECDSA".equals(key.getAlgorithm())
                && fieldSizeFromKey((ECKey) key) == fieldSize;
    }

    private static int fieldSizeFromKey(ECKey ecPublicKey) {
        return ecPublicKey.getParams().getCurve().getField().getFieldSize();
    }
}
