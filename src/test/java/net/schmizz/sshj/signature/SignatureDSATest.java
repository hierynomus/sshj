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
package net.schmizz.sshj.signature;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.Arrays;

import com.hierynomus.sshj.common.KeyAlgorithm;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.IOUtils;

public class SignatureDSATest {

    private KeyFactory keyFactory;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        keyFactory = KeyFactory.getInstance(KeyAlgorithm.DSA);
    }

    @Test
    public void testSignAndVerify() throws Exception {
        BigInteger x = new BigInteger(new byte[] { 58, 19, -71, -30, 89, -111, 75, 98, 110, 38, -56, -23, 68, 74, -40, 17, -30, 37, 50, 35 });
        BigInteger y = new BigInteger(new byte[] { 32, -91, -39, 54, 19, 14, 26, 113, -109, -92, -45, 83, -86, 23, -103, 108, 102, 86, 110, 78, -45, -41, -37, 38, -94, -92, -124, -36, -93, 92, 127, 113, 97, -119, -10, -73, -41, -45, 98, -104, -54, -9, -92, 66, 15, 31, 68, -32, 32, -121, -51, 68, 29, 100, 59, 60, 109, 111, -81, 80, 7, 127, 116, -107, 88, -114, -114, -69, 41, -15, 59, 81, 70, 9, -113, 36, 119, 28, 16, -127, -65, 32, -19, 109, -27, 24, -48, -80, 84, 47, 119, 25, 57, -118, -66, -22, -105, -11, 112, 16, -91, -127, 62, 23, 89, -17, -43, -105, -4, -43, 60, 42, -81, -95, -27, -8, 98, -37, 120, 80, -76, 93, -24, -104, -117, 38, -56, -68 });
        BigInteger p = new BigInteger(new byte[] { 0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68, 0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70, 48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57 });
        BigInteger q = new BigInteger(new byte[] { 0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11 });
        BigInteger g = new BigInteger(new byte[] { 0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117, 84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5, 98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42 });

        byte[] data = "The Magic Words are Squeamish Ossifrage".getBytes(IOUtils.UTF8);

        // A previously signed and verified signature using the data and DSA key parameters above.
        byte[] dataSig = new byte[] { 0, 0, 0, 7, 115, 115, 104, 45, 100, 115, 115, 0, 0, 0, 40, 40, -71, 33, 105, -89, -107, 8, 26, -13, -90, 73, -103, 105, 112, 7, -59, -66, 46, 85, -27, 20, 82, 22, -113, -75, -86, -121, -42, -73, 78, 66, 93, -34, 39, -50, -93, 27, -5, 37, -92 };

        SignatureDSA signatureForSigning = new SignatureDSA();
        signatureForSigning.initSign(keyFactory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g)));
        signatureForSigning.update(data);
        byte[] sigBlob = signatureForSigning.encode(signatureForSigning.sign());
        byte[] sigFull = new Buffer.PlainBuffer().putString("ssh-dss").putBytes(sigBlob).getCompactData();

        SignatureDSA signatureForVerifying = new SignatureDSA();
        signatureForVerifying.initVerify(keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g)));
        signatureForVerifying.update(data);
        Assert.assertTrue("Failed to verify signature: " + Arrays.toString(sigFull), signatureForVerifying.verify(sigFull));
        signatureForVerifying.update(data);
        Assert.assertTrue("Failed to verify signature: " + Arrays.toString(dataSig), signatureForVerifying.verify(dataSig));
    }

}
