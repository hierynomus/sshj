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
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.method.AuthMethod;
import net.schmizz.sshj.userauth.method.KeyedAuthMethod;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * The {@code "publickey"} authentication method backed by an SSH agent, for a single agent identity.
 * <p>
 * It behaves exactly like {@link net.schmizz.sshj.userauth.method.AuthPublickey} - send the public
 * key, and on {@code SSH_MSG_USERAUTH_PK_OK} send a signed request - except the signature is
 * produced by the {@link AgentProxy} (which drives the hardware, PIN and touch) and used verbatim.
 * This is how FIDO/U2F security keys ({@code sk-*}) authenticate: the agent returns a complete
 * signature with the security-key flags and counter already appended.
 * <p>
 * Use {@link #fromIdentities(AgentProxy)} to turn every identity the agent holds into a method:
 * <pre>{@code
 *   try (AgentProxy agent = AgentProxy.fromEnvironment()) {
 *       ssh.auth(username, AuthAgent.fromIdentities(agent));
 *   }
 * }</pre>
 */
public class AuthAgent extends KeyedAuthMethod {

    private final AgentProxy agent;
    private final AgentIdentity identity;

    public AuthAgent(AgentProxy agent, AgentIdentity identity) {
        super("publickey", new AgentKeyProvider(identity));
        this.agent = agent;
        this.identity = identity;
    }

    /**
     * Build one {@link AuthAgent} method per identity the agent currently holds, ready to hand to
     * {@link net.schmizz.sshj.SSHClient#auth(String, Iterable)}.
     */
    public static List<AuthMethod> fromIdentities(AgentProxy agent) throws IOException {
        List<AuthMethod> methods = new ArrayList<>();
        for (AgentIdentity identity : agent.getIdentities()) {
            methods.add(new AuthAgent(agent, identity));
        }
        return methods;
    }

    @Override
    public void handle(Message cmd, SSHPacket buf) throws UserAuthException, TransportException {
        if (cmd == Message.USERAUTH_60) {
            sendSignedRequest();
        } else {
            super.handle(cmd, buf);
        }
    }

    @Override
    protected SSHPacket buildReq() throws UserAuthException {
        // Feeler request, no signature.
        return putPubKey(super.buildReq().putBoolean(false));
    }

    private void sendSignedRequest() throws UserAuthException, TransportException {
        SSHPacket req = putPubKey(super.buildReq().putBoolean(true));
        byte[] dataToSign = new Buffer.PlainBuffer()
                .putString(params.getTransport().getSessionID())
                .putBuffer(req)
                .getCompactData();
        byte[] signature;
        try {
            signature = agent.sign(identity.getKeyBlob(), dataToSign, agentSignFlags());
        } catch (IOException e) {
            throw new UserAuthException("SSH agent failed to sign for " + identity, e);
        }
        // The agent returns a fully formed SSH signature value; write it as a single string.
        req.putString(signature);
        params.getTransport().write(req);
    }

    @Override
    protected SSHPacket putPubKey(SSHPacket reqBuf) throws UserAuthException {
        KeyType keyType = identityType();
        try {
            KeyAlgorithm keyAlgorithm = getPublicKeyAlgorithm(keyType);
            if (keyAlgorithm == null) {
                throw new UserAuthException("No KeyAlgorithm configured for agent key " + keyType);
            }
            // Use the exact key blob the agent gave us, so signature verification matches byte-for-byte.
            reqBuf.putString(keyAlgorithm.getKeyAlgorithm()).putString(identity.getKeyBlob());
            return reqBuf;
        } catch (TransportException e) {
            throw new UserAuthException("No KeyAlgorithm configured for agent key " + keyType, e);
        }
    }

    private int agentSignFlags() throws UserAuthException {
        try {
            KeyAlgorithm keyAlgorithm = getPublicKeyAlgorithm(identityType());
            String name = keyAlgorithm == null ? "" : keyAlgorithm.getKeyAlgorithm();
            if ("rsa-sha2-512".equals(name)) {
                return AgentProxy.SSH_AGENT_RSA_SHA2_512;
            }
            if ("rsa-sha2-256".equals(name)) {
                return AgentProxy.SSH_AGENT_RSA_SHA2_256;
            }
            return 0;
        } catch (TransportException e) {
            throw new UserAuthException("Could not resolve key algorithm for agent key", e);
        }
    }

    private KeyType identityType() {
        return KeyType.fromKey(identity.getPublicKey());
    }

    /** Exposes the agent identity's public key to {@link KeyedAuthMethod}; signing happens via the agent. */
    private static final class AgentKeyProvider implements KeyProvider {
        private final AgentIdentity identity;

        private AgentKeyProvider(AgentIdentity identity) {
            this.identity = identity;
        }

        @Override
        public PrivateKey getPrivate() {
            throw new UnsupportedOperationException("Agent-held keys are signed by the agent, not locally");
        }

        @Override
        public PublicKey getPublic() {
            return identity.getPublicKey();
        }

        @Override
        public KeyType getType() {
            return KeyType.fromKey(identity.getPublicKey());
        }
    }
}
