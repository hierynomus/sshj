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
* Copyright 2010, 2011 sshj contributors
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
package net.schmizz.sshj.util;

import com.hierynomus.sshj.common.KeyAlgorithm;
import net.schmizz.sshj.common.SecurityUtils;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class KeyUtil {

    /** Creates a DSA private key. */
    public static PrivateKey newDSAPrivateKey(String x, String p, String q, String g)
            throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(KeyAlgorithm.DSA).generatePrivate(new DSAPrivateKeySpec(new BigInteger(x, 16),
                                                                                        new BigInteger(p, 16),
                                                                                        new BigInteger(q, 16),
                                                                                        new BigInteger(g, 16))
        );
    }

    /** Creates a DSA public key. */
    public static PublicKey newDSAPublicKey(String y, String p, String q, String g)
            throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(KeyAlgorithm.DSA).generatePublic(new DSAPublicKeySpec(new BigInteger(y, 16),
                                                                                      new BigInteger(p, 16),
                                                                                      new BigInteger(q, 16),
                                                                                      new BigInteger(g, 16))
        );
    }

    /** Creates an RSA private key. */
    public static PrivateKey newRSAPrivateKey(String modulus, String exponent)
            throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(KeyAlgorithm.RSA).generatePrivate(new RSAPrivateKeySpec(new BigInteger(modulus, 16),
                                                                                        new BigInteger(exponent, 16))
        );
    }

    /** Creates an RSA public key. */
    public static PublicKey newRSAPublicKey(String modulus, String exponent)
            throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(KeyAlgorithm.RSA).generatePublic(new RSAPublicKeySpec(new BigInteger(modulus, 16),
                                                                                      new BigInteger(exponent, 16)));
    }

}
