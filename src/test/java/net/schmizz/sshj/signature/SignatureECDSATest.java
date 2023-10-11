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

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Buffer.BufferException;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignatureECDSATest {

    @Test
    public void testECDSA256Verifies() throws BufferException {
        byte[] K_S = fromString("0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, -8, 35, 96, -97, 65, -33, -128, -58, -64, -73, -51, 10, -28, 20, -59, 86, -88, -24, 126, 29, 115, 26, -88, 31, -115, 87, -109, -4, 61, 108, 28, 31, -66, 79, 107, 17, 24, 93, 114, -25, 121, 57, -58, 10, 26, -36, -100, -120, -7, -103, 86, 72, -109, -82, 111, 73, 4, -98, 58, 28, -3, -91, 28, 84");
        byte[] H = fromString("61, 55, -62, -122, -93, 82, -63, 25, -52, -13, -41, -29, 78, 101, 22, -75, 113, 59, -72, -92, -2, 39, -52, -89, 127, 80, -77, -82, 67, 3, -21, -53");
        byte[] sig = fromString("0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 73, 0, 0, 0, 33, 0, -19, 50, -123, -35, 93, 50, 3, 40, -79, 110, -99, 6, -78, 40, -31, -26, -119, 113, -101, 109, -27, 12, 47, -119, -83, 107, -7, 116, 2, 97, 84, 32, 0, 0, 0, 32, 69, -44, 52, -119, 22, -60, -33, -105, -41, 45, 36, 112, -59, 49, -90, -110, -13, -114, 115, -86, 29, 30, 127, -44, 96, 57, -49, 39, -83, 50, -8, 123");

        PublicKey hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();

        Signature signature = new SignatureECDSA.Factory256().create();
        signature.initVerify(hostKey);
        signature.update(H, 0, H.length);

        assertTrue(signature.verify(sig), "ECDSA256 signature verifies");
    }

    @Test
    public void testECDSA384Verifies() throws BufferException {
        byte[] K_S = fromString("0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 0, 0, 0, 8, 110, 105, 115, 116, 112, 51, 56, 52, 0, 0, 0, 97, 4, 105, 52, -67, 89, 21, 53, -125, -26, -23, -125, 48, 119, -63, -66, 30, -46, -110, 21, 14, -96, -28, 40, -108, 60, 120, 110, 58, 30, -56, 37, 6, -17, -25, 109, 84, 67, -19, 0, -30, -33, 54, 94, -121, 49, 68, -66, 14, 6, 76, -51, 102, -123, 59, -24, -34, 79, -51, 64, -48, -45, 21, -42, -96, -123, -27, -21, 15, 56, -96, -12, 73, -10, 113, -20, -22, 38, 100, 38, -85, -113, 46, 36, 17, -30, 89, 40, 16, 104, 123, 50, 8, 122, 49, -41, -97, 95");
        byte[] H = fromString("-46, 22, -52, 62, -100, -43, -68, -88, 98, 31, 116, -77, 27, -92, 127, 25, -43, -63, -42, -106, -53, 26, -61, 69, -38, -73, 94, -70, -99, -6, -78, 61");
        byte[] sig = fromString("0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 51, 56, 52, 0, 0, 0, 105, 0, 0, 0, 48, 58, -5, -53, 17, -127, -32, 74, 123, -84, -1, 80, 96, 49, -77, -109, 22, -90, 115, -111, 40, 2, 4, 56, 51, 92, -30, 39, -61, -92, -76, -105, 45, 52, -31, 116, 44, -32, -65, 57, 44, 26, 45, 59, -115, 95, 113, 114, -89, 0, 0, 0, 49, 0, -56, 65, 59, 111, -26, -72, 127, 47, -15, 14, -34, 56, 5, 34, 28, -78, -13, 26, -22, -41, -86, -36, -112, 10, 91, 48, -77, -84, 93, 111, -84, 59, 42, -128, -22, 91, -4, -31, -89, -37, 107, -27, 28, -119, -36, 93, 25, -49");

        PublicKey hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();

        Signature signature = new SignatureECDSA.Factory384().create();
        signature.initVerify(hostKey);
        signature.update(H, 0, H.length);

        assertTrue(signature.verify(sig), "ECDSA384 signature verifies");
    }

    @Test
    public void testECDSA521Verifies() throws BufferException {
        byte[] K_S = fromString("0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 0, 0, 0, 8, 110, 105, 115, 116, 112, 53, 50, 49, 0, 0, 0, -123, 4, 1, -56, 55, 64, -73, -109, 95, 94, -107, -116, -46, -16, 119, -66, -68, 41, -103, -66, 102, -123, -69, 59, -8, 106, 72, 75, 7, 56, -79, 109, -88, 77, 12, -97, -109, -32, -60, 64, -75, -48, 50, -51, -68, -81, 75, 110, -7, -79, -32, -36, -73, -7, -65, -24, 40, -74, 58, 43, -26, -5, -55, 125, -32, -89, -54, -111, 0, 81, 37, -73, 60, 69, 107, -108, 115, 60, -61, 22, 6, -128, -69, -28, 122, -26, -37, -117, 121, -106, -126, 23, -90, 127, 73, -58, -113, -61, 105, 68, 116, 85, -115, -47, 90, 122, 109, -21, 127, 39, -75, -58, -109, 73, -82, -122, -11, -44, -87, 85, -100, -4, -123, -31, 126, -94, 127, 96, 9, -30, 70, -113, -42, 28");
        byte[] H = fromString("-36, -107, -95, 2, 93, -111, -19, -107, 118, -7, 116, -33, 58, -90, -63, -60, -5, -23, 7, 56, -128, -22, -15, 26, -97, 2, 50, -93, 21, -21, 69, 105");
        byte[] sig = fromString("0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 53, 50, 49, 0, 0, 0, -117, 0, 0, 0, 66, 1, 31, -111, 69, -37, 33, 24, -95, 53, -124, -33, 41, 65, -96, -112, -102, -33, 123, 30, -108, 102, 127, -27, 72, 101, -108, -123, 6, 107, 83, -72, -121, 87, -86, 75, 114, 50, -60, -75, -46, 7, -63, 84, -114, -91, 113, 52, 26, 102, -11, 76, 99, 9, 19, -73, -42, -3, 57, 41, -42, 13, -81, 18, -3, -49, -50, 0, 0, 0, 65, 102, 60, -2, 123, 91, -8, 120, 42, 118, 118, -9, -112, 72, 8, 61, -49, -45, 63, 112, 61, -55, -122, -109, 4, -39, 95, 3, -4, -43, 98, 39, 4, 63, 78, 78, 51, 77, 75, -23, 19, -46, 117, -115, -95, 90, -43, 108, -47, -90, 84, 98, 50, -97, -37, -14, -115, -76, 14, -61, 91, 107, 23, -112, 22, -15");

        PublicKey hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();

        Signature signature = new SignatureECDSA.Factory521().create();
        signature.initVerify(hostKey);
        signature.update(H, 0, H.length);

        assertTrue(signature.verify(sig), "ECDSA521 signature verifies");
    }

    private byte[] fromString(String string) {
        String[] split = string.split(", ");
        byte[] res = new byte[split.length];

        for (int i = 0; i < split.length; i++)
            res[i] = Byte.parseByte(split[i]);

        return res;
    }
}
