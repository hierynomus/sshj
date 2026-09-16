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
package com.hierynomus.sshj.userauth.method;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end regression check that publickey auth against a real (in-process Apache MINA) SSH
 * server still succeeds now that {@code SSH_MSG_EXT_INFO}'s {@code server-sig-algs} extension
 * (RFC 8308) is parsed and used to reorder candidate signature algorithms
 * ({@link net.schmizz.sshj.userauth.method.KeyedAuthMethod}). MINA SSHD advertises
 * {@code server-sig-algs} by default, so this exercises the real parse-and-reorder path, not just
 * the unit-level behavior.
 */
public class AuthPublickeyExtInfoTest {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension(false);

    @BeforeEach
    public void setUp() throws IOException {
        fixture.getServer().setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        fixture.getServer().start();
    }

    @Test
    public void authenticatesWithRsaKeyAfterServerSigAlgsNegotiation() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        KeyProvider keyProvider = new KeyProvider() {
            @Override
            public PrivateKey getPrivate() {
                return keyPair.getPrivate();
            }

            @Override
            public PublicKey getPublic() {
                return keyPair.getPublic();
            }

            @Override
            public KeyType getType() {
                return KeyType.RSA;
            }
        };

        SSHClient client = fixture.setupConnectedDefaultClient();
        client.auth("jeroen", new AuthPublickey(keyProvider));

        assertTrue(client.isAuthenticated(), "client should authenticate with an RSA key once server-sig-algs is parsed");
    }
}
