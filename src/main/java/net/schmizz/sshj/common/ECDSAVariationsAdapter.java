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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.sshj.secg.SecgUtils;

public class ECDSAVariationsAdapter {

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

    public static PublicKey readPubKeyFromBuffer(Buffer<?> buf, String variation) throws GeneralSecurityException {
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

            X9ECParameters ecParams = NISTNamedCurves.getByName(NIST_CURVES_NAMES.get(variation));
            ECPoint pPublicPoint = ecParams.getCurve().createPoint(bigX, bigY);
            ECParameterSpec spec = new ECParameterSpec(ecParams.getCurve(), ecParams.getG(), ecParams.getN());
            ECPublicKeySpec publicSpec = new ECPublicKeySpec(pPublicPoint, spec);

            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
            return keyFactory.generatePublic(publicSpec);
        } catch (Exception ex) {
            throw new GeneralSecurityException(ex);
        }
    }

    public static void writePubKeyContentsIntoBuffer(PublicKey pk, Buffer<?> buf) {
        final ECPublicKey ecdsa = (ECPublicKey) pk;
        byte[] encoded = SecgUtils.getEncoded(ecdsa.getW(), ecdsa.getParams().getCurve());

        buf.putString(Integer.toString(fieldSizeFromKey(ecdsa)))
            .putBytes(encoded);
    }

    public static int fieldSizeFromKey(ECPublicKey ecPublicKey) {
        return ecPublicKey.getParams().getCurve().getField().getFieldSize();
    }

}
