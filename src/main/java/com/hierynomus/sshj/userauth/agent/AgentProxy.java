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

import net.schmizz.sshj.common.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * A client for the SSH authentication agent protocol (draft-miller-ssh-agent / OpenSSH's
 * {@code PROTOCOL.agent}).
 * <p>
 * This is the recommended way to authenticate with a FIDO/U2F security key (an
 * {@code sk-ecdsa-sha2-nistp256@openssh.com} or {@code sk-ssh-ed25519@openssh.com} key): load the
 * key into your agent once with {@code ssh-add}, and the agent performs the hardware tap on every
 * sign. The agent returns a fully formed SSH signature - including the security-key flags and
 * counter - so sshj forwards it verbatim and never has to talk to the hardware itself.
 * <p>
 * It works for ordinary keys too (RSA, ECDSA, Ed25519), so it doubles as general ssh-agent support.
 */
public class AgentProxy implements Closeable {

    private static final byte SSH_AGENT_FAILURE = 5;
    private static final byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
    private static final byte SSH_AGENT_IDENTITIES_ANSWER = 12;
    private static final byte SSH_AGENTC_SIGN_REQUEST = 13;
    private static final byte SSH_AGENT_SIGN_RESPONSE = 14;

    /** Sign flag asking the agent for an {@code rsa-sha2-256} signature from an RSA key. */
    public static final int SSH_AGENT_RSA_SHA2_256 = 2;
    /** Sign flag asking the agent for an {@code rsa-sha2-512} signature from an RSA key. */
    public static final int SSH_AGENT_RSA_SHA2_512 = 4;

    /** OpenSSH caps a single agent message at 256 KiB. */
    private static final int AGENT_MAX_MESSAGE_LENGTH = 256 * 1024;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final AgentConnection connection;
    private final DataInputStream in;
    private final OutputStream out;

    public AgentProxy(AgentConnection connection) throws IOException {
        this.connection = connection;
        this.in = new DataInputStream(connection.getInputStream());
        this.out = connection.getOutputStream();
    }

    /**
     * Connect to the agent indicated by the {@code SSH_AUTH_SOCK} environment variable over a unix-
     * domain socket. Requires a Java 16+ runtime; on older runtimes construct an {@link AgentProxy}
     * with your own {@link AgentConnection}.
     *
     * @throws IOException if {@code SSH_AUTH_SOCK} is unset or the agent cannot be reached
     */
    public static AgentProxy fromEnvironment() throws IOException {
        String socketPath = System.getenv("SSH_AUTH_SOCK");
        if (socketPath == null || socketPath.isEmpty()) {
            throw new IOException("SSH_AUTH_SOCK is not set; no SSH agent is available");
        }
        return new AgentProxy(new UnixSocketAgentConnection(socketPath));
    }

    /**
     * List the identities the agent holds. Identities whose key type sshj does not understand are
     * skipped (logged at debug), rather than failing the whole listing.
     */
    public synchronized List<AgentIdentity> getIdentities() throws IOException {
        writeMessage(SSH_AGENTC_REQUEST_IDENTITIES, new byte[0]);
        Response response = readMessage();
        if (response.type != SSH_AGENT_IDENTITIES_ANSWER) {
            throw new IOException("Unexpected response to agent identities request: type " + response.type);
        }
        Buffer.PlainBuffer buf = new Buffer.PlainBuffer(response.contents);
        List<AgentIdentity> identities = new ArrayList<>();
        try {
            long count = buf.readUInt32();
            for (long i = 0; i < count; i++) {
                byte[] keyBlob = buf.readBytes();
                String comment = buf.readString();
                try {
                    PublicKey publicKey = new Buffer.PlainBuffer(keyBlob).readPublicKey();
                    identities.add(new AgentIdentity(publicKey, keyBlob, comment));
                } catch (Exception e) {
                    log.debug("Skipping agent identity '{}' of unsupported key type: {}", comment, e.toString());
                }
            }
        } catch (Buffer.BufferException e) {
            throw new IOException("Malformed agent identities answer", e);
        }
        return identities;
    }

    /**
     * Ask the agent to sign {@code data} with the key identified by {@code keyBlob}.
     *
     * @param keyBlob the identity's key blob, exactly as returned by {@link #getIdentities()}
     * @param data    the data to sign
     * @param flags   sign flags, e.g. {@link #SSH_AGENT_RSA_SHA2_256}; {@code 0} for Ed25519 and
     *                security keys
     * @return the SSH signature value ({@code string signature_format || string signature_blob}, with
     * any security-key flags and counter already appended by the agent), ready to be written as a
     * single SSH {@code string}
     */
    public synchronized byte[] sign(byte[] keyBlob, byte[] data, int flags) throws IOException {
        byte[] request = new Buffer.PlainBuffer()
                .putBytes(keyBlob)
                .putBytes(data)
                .putUInt32(flags & 0xffffffffL)
                .getCompactData();
        writeMessage(SSH_AGENTC_SIGN_REQUEST, request);
        Response response = readMessage();
        if (response.type != SSH_AGENT_SIGN_RESPONSE) {
            throw new IOException(response.type == SSH_AGENT_FAILURE
                    ? "Agent declined to sign (it may not hold this key, or the user cancelled the touch/PIN)"
                    : "Unexpected response to agent sign request: type " + response.type);
        }
        try {
            return new Buffer.PlainBuffer(response.contents).readBytes();
        } catch (Buffer.BufferException e) {
            throw new IOException("Malformed agent sign response", e);
        }
    }

    @Override
    public void close() throws IOException {
        connection.close();
    }

    private void writeMessage(byte type, byte[] contents) throws IOException {
        int length = 1 + contents.length;
        byte[] header = new byte[]{
                (byte) (length >>> 24), (byte) (length >>> 16), (byte) (length >>> 8), (byte) length, type
        };
        out.write(header);
        out.write(contents);
        out.flush();
    }

    private Response readMessage() throws IOException {
        int length = in.readInt();
        if (length <= 0 || length > AGENT_MAX_MESSAGE_LENGTH) {
            throw new IOException("Illegal agent message length: " + length);
        }
        byte type = in.readByte();
        byte[] contents = new byte[length - 1];
        in.readFully(contents);
        return new Response(type, contents);
    }

    private static final class Response {
        private final byte type;
        private final byte[] contents;

        private Response(byte type, byte[] contents) {
            this.type = type;
            this.contents = contents;
        }
    }
}
