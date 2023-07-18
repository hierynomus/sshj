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
package net.schmizz.sshj.signature

import com.hierynomus.sshj.common.KeyAlgorithm
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.DSAPublicKeySpec

class SignatureDSASpec extends Specification {

    def keyFactory = KeyFactory.getInstance(KeyAlgorithm.DSA)

    private PublicKey createPublicKey(final byte[] y, final byte[] p, final byte[] q, final byte[] g) throws Exception {
        final BigInteger publicKey = new BigInteger(y);
        final BigInteger prime = new BigInteger(p);
        final BigInteger subPrime = new BigInteger(q);
        final BigInteger base = new BigInteger(g);
        final DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(publicKey, prime, subPrime, base);
        return keyFactory.generatePublic(dsaPubKeySpec);
    }


    @Unroll
    def "should verify signature"() {
        given:
        def signatureDSA = new SignatureDSA()
        def publicKey = createPublicKey(y, p, q, g)
        signatureDSA.initVerify(publicKey)

        when:
        signatureDSA.update(H)

        then:
        signatureDSA.verify(H_sig)

        where:
        y << [[103, 23, -102, -4, -110, -90, 66, -52, -14, 125, -16, -76, -110, 33, -111, -113, -46, 27, -118, -73, 0, -19, -48, 43, -102, 56, -49, -84, 118, -10, 76, 84, -5, 84, 55, 72, -115, -34, 95, 80, 32, -120, 57, 101, -64, 111, -37, -26, 96, 55, -98, -24, -99, -81, 60, 22, 5, -55, 119, -95, -28, 114, -40, 13, 97, 65, 22, 33, 117, -59, 22, 81, -56, 98, -112, 103, -62, 90, -12, 81, 61, -67, 104, -24, 67, -18, -60, 78, -127, 44, 13, 11, -117, -118, -69, 89, -25, 26, 103, 72, -83, 114, -40, -124, -10, -31, -34, -49, -54, -15, 92, 79, -40, 14, -12, 58, -112, -30, 11, 48, 26, 121, 105, -68, 92, -93, 99, -78] as byte[],
              [0, -92, 59, 5, 72, 124, 101, 124, -18, 114, 7, 100, 98, -61, 73, -104, 120, -98, 54, 118, 17, -62, 91, -110, 29, 98, 50, -101, -41, 99, -116, 101, 107, -123, 124, -97, 62, 119, 88, -109, -110, -1, 109, 119, -51, 69, -98, -105, 2, -69, -121, -82, -118, 23, -6, 96, -61, -65, 102, -58, -74, 32, -104, 116, -6, -35, -83, -10, -88, -68, 106, -112, 72, -2, 35, 38, 15, -11, -22, 30, -114, -46, -47, -18, -17, -71, 24, -25, 28, 13, 29, -40, 101, 18, 81, 45, -120, -67, -53, -41, 11, 50, -89, -33, 50, 54, -14, -91, -35, 12, -42, 13, -84, -19, 100, -3, -85, -18, 74, 99, -49, 64, -49, 51, -83, -82, -127, 116, 64] as byte[]]
        p << [[0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68,
               0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70,
               48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92,
               -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21,
               15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41,
               42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57] as byte[],
              [0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68,
               0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70,
               48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92,
               -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21,
               15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41,
               42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57] as byte[]]
        q << [[0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11] as byte[],
              [0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11] as byte[]]
        g << [[0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58,
               -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127,
               -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117,
               84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5,
               98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110,
               -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42] as byte[],
              [0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58,
               -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127,
               -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117,
               84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5,
               98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110,
               -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42] as byte[]]
        H << [[-13, 20, 103, 73, 115, -68, 113, 74, -25, 12, -90, 19, 56, 73, -7, -49, -118, 107, -69, -39, -6, 82, -123,
               54, -10, -43, 16, -117, -59, 36, -49, 27] as byte[],
              [-4, 111, -103, 111, 72, -106, 105, -19, 81, -123, 84, -13, -40, -53, -3, -97, -8, 43, -22, -2, -23, -15, 28,
               116, -63, 96, -79, -127, -84, 63, -6, -94] as byte[]]
        H_sig << [[0, 0, 0, 7, 115, 115, 104, 45, 100, 115, 115, 0, 0, 0, 40, -113, -52, 88, -117, 80, -105, -92, -124, -49,
                   56, -35, 90, -9, -128, 31, -33, -18, 13, -5, 7, 108, -2, 92, 108, 85, 58, 39, 99, 122, -118, 125, -121, 21,
                   -37, 2, 55, 109, -23, -125, 4] as byte[],
                  [0, 0, 0, 7, 115, 115, 104, 45, 100, 115, 115, 0, 0, 0, 40, 0, 79, 84, 118, -50, 11, -117, -112, 52, -25,
                   -78, -50, -20, 6, -69, -26, 7, 90, -34, -124, 80, 76, -32, -23, -8, 43, 38, -48, -89, -17, -60, -1, -78,
                   112, -88, 14, -39, -78, -98, -80] as byte[]]
    }

}
