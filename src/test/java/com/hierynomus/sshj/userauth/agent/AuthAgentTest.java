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
package com.hierynomus.sshj.userauth.agent;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.SSHClient;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Authenticates to a real (in-process Apache MINA) SSH server via {@link AuthAgent}, with signing
 * delegated to an in-memory {@link FakeSshAgent}. This proves the full agent auth flow: the agent
 * lists the identity, the server sends PK_OK, the agent signs the userauth blob, and the server
 * verifies the signature. (A FIDO security key authenticates by exactly this path, with a YubiKey
 * standing in for the fake agent.)
 */
public class AuthAgentTest {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension(false);

    @BeforeEach
    public void setUp() throws IOException {
        fixture.getServer().setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        fixture.getServer().start();
    }

    @Test
    public void authenticatesWithEd25519AgentKey() throws Exception {
        authenticatesWith(KeyPairGenerator.getInstance("Ed25519").generateKeyPair(), "ed25519-agent-key");
    }

    @Test
    public void authenticatesWithEcdsaAgentKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        authenticatesWith(kpg.generateKeyPair(), "ecdsa-agent-key");
    }

    private void authenticatesWith(KeyPair keyPair, String comment) throws Exception {
        try (FakeSshAgent fakeAgent = new FakeSshAgent()
                .addIdentity(keyPair.getPublic(), keyPair.getPrivate(), comment)
                .start()) {
            AgentProxy agent = new AgentProxy(fakeAgent.connection());

            List<AgentIdentity> identities = agent.getIdentities();
            assertEquals(1, identities.size());
            assertEquals(comment, identities.get(0).getComment());

            SSHClient client = fixture.setupConnectedDefaultClient();
            client.auth("jeroen", new AuthAgent(agent, identities.get(0)));
            assertTrue(client.isAuthenticated(), "client should authenticate via the agent");
        }
    }
}
