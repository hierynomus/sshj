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
package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.transport.random.JCERandom;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class Curve25519DHTest {

    private static final String ALGORITHM_FILTER = "KeyPairGenerator.X25519";

    private static final int KEY_LENGTH = 32;

    private static final byte[] PEER_PUBLIC_KEY = {
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8
    };

    @BeforeEach
    @AfterEach
    public void clearSecurityProvider() {
        SecurityUtils.setSecurityProvider(null);
    }

    @Test
    public void testInitPublicKeyLength() throws GeneralSecurityException {
        final boolean bouncyCastleRegistrationRequired = isAlgorithmUnsupported();
        SecurityUtils.setRegisterBouncyCastle(bouncyCastleRegistrationRequired);

        final Curve25519DH dh = new Curve25519DH();
        dh.init(null, new JCERandom.Factory());

        final byte[] publicKeyEncoded = dh.getE();

        assertNotNull(publicKeyEncoded);
        assertEquals(KEY_LENGTH, publicKeyEncoded.length);
    }

    @Test
    public void testInitComputeSharedSecretKey() throws GeneralSecurityException {
        SecurityUtils.setRegisterBouncyCastle(true);

        final Curve25519DH dh = new Curve25519DH();
        dh.init(null, new JCERandom.Factory());

        dh.computeK(PEER_PUBLIC_KEY);
        final BigInteger sharedSecretKey = dh.getK();

        assertNotNull(sharedSecretKey);
        assertEquals(BigInteger.ONE.signum(), sharedSecretKey.signum());
    }

    private boolean isAlgorithmUnsupported() {
        final Provider[] providers = Security.getProviders(ALGORITHM_FILTER);
        return providers == null || providers.length == 0;
    }
}
