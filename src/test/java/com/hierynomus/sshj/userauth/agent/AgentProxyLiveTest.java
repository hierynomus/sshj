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

import com.hierynomus.sshj.key.KeyAlgorithm;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.signature.Signature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test against a real, running ssh-agent over a unix-domain socket. It exercises the
 * reflective {@link UnixSocketAgentConnection}, identity listing and the sign request, then verifies
 * the agent's signature with sshj's own signature machinery.
 * <p>
 * Opt-in: it only runs when {@code SSHJ_TEST_AGENT_SOCK} points at an agent socket that holds at
 * least one key, so ordinary CI is unaffected. See {@code AgentLiveTest} orchestration in the PR
 * notes for how to drive it. Requires a Java 16+ runtime for unix-domain sockets.
 */
@EnabledIfEnvironmentVariable(named = "SSHJ_TEST_AGENT_SOCK", matches = ".+")
public class AgentProxyLiveTest {

    @Test
    public void listsIdentitiesAndProducesVerifiableSignatures() throws Exception {
        String socketPath = System.getenv("SSHJ_TEST_AGENT_SOCK");
        try (AgentProxy agent = new AgentProxy(new UnixSocketAgentConnection(socketPath))) {
            List<AgentIdentity> identities = agent.getIdentities();
            assertFalse(identities.isEmpty(), "the test agent should hold at least one identity");

            byte[] data = "sshj agent live test challenge".getBytes(StandardCharsets.UTF_8);
            for (AgentIdentity identity : identities) {
                byte[] signature = agent.sign(identity.getKeyBlob(), data, 0);

                String signatureType = new Buffer.PlainBuffer(signature).readString();
                Signature verifier = signatureForType(signatureType);
                verifier.initVerify(identity.getPublicKey());
                verifier.update(data);
                assertTrue(verifier.verify(signature),
                        "agent signature should verify for " + identity + " (" + signatureType + ")");
            }
        }
    }

    private static Signature signatureForType(String signatureName) {
        for (Factory.Named<KeyAlgorithm> factory : new DefaultConfig().getKeyAlgorithms()) {
            Signature signature = factory.create().newSignature();
            if (signature.getSignatureName().equals(signatureName)) {
                return signature;
            }
        }
        throw new IllegalStateException("No registered Signature for agent signature type: " + signatureName);
    }
}
