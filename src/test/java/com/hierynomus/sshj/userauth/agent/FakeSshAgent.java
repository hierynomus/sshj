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
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * A minimal in-memory SSH agent for tests: it speaks the agent wire protocol over loopback pipes and
 * signs with software keys. This lets the agent auth path be tested end-to-end against a real SSH
 * server without any external agent process or hardware.
 */
class FakeSshAgent implements Closeable {

    private static final byte SSH_AGENT_FAILURE = 5;
    private static final byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
    private static final byte SSH_AGENT_IDENTITIES_ANSWER = 12;
    private static final byte SSH_AGENTC_SIGN_REQUEST = 13;
    private static final byte SSH_AGENT_SIGN_RESPONSE = 14;

    private static final class Identity {
        final byte[] keyBlob;
        final String comment;
        final PrivateKey privateKey;
        final Signature signature;

        Identity(byte[] keyBlob, String comment, PrivateKey privateKey, Signature signature) {
            this.keyBlob = keyBlob;
            this.comment = comment;
            this.privateKey = privateKey;
            this.signature = signature;
        }
    }

    private final List<Identity> identities = new ArrayList<>();
    private final DataInputStream agentIn;
    private final OutputStream agentOut;
    private final InputStream clientIn;
    private final OutputStream clientOut;
    private final Thread thread;

    FakeSshAgent() throws IOException {
        PipedInputStream clientToAgent = new PipedInputStream(1 << 16);
        PipedOutputStream clientWrites = new PipedOutputStream(clientToAgent);
        PipedInputStream agentToClient = new PipedInputStream(1 << 16);
        PipedOutputStream agentWrites = new PipedOutputStream(agentToClient);

        this.agentIn = new DataInputStream(clientToAgent);
        this.agentOut = agentWrites;
        this.clientIn = agentToClient;
        this.clientOut = clientWrites;

        this.thread = new Thread(this::serve, "fake-ssh-agent");
        this.thread.setDaemon(true);
    }

    FakeSshAgent addIdentity(PublicKey publicKey, PrivateKey privateKey, String comment) {
        byte[] keyBlob = new Buffer.PlainBuffer().putPublicKey(publicKey).getCompactData();
        Signature signature = signatureFor(KeyType.fromKey(publicKey));
        identities.add(new Identity(keyBlob, comment, privateKey, signature));
        return this;
    }

    FakeSshAgent start() {
        thread.start();
        return this;
    }

    AgentConnection connection() {
        return new AgentConnection() {
            @Override
            public InputStream getInputStream() {
                return clientIn;
            }

            @Override
            public OutputStream getOutputStream() {
                return clientOut;
            }

            @Override
            public void close() {
                // The proxy closing its side ends the serve loop via EOF.
            }
        };
    }

    private void serve() {
        try {
            while (true) {
                int length = agentIn.readInt();
                byte type = agentIn.readByte();
                byte[] contents = new byte[length - 1];
                agentIn.readFully(contents);
                handle(type, contents);
            }
        } catch (IOException eof) {
            // pipe closed -> stop
        }
    }

    private void handle(byte type, byte[] contents) throws IOException {
        switch (type) {
            case SSH_AGENTC_REQUEST_IDENTITIES:
                Buffer.PlainBuffer answer = new Buffer.PlainBuffer().putUInt32(identities.size());
                for (Identity identity : identities) {
                    answer.putBytes(identity.keyBlob).putString(identity.comment);
                }
                writeMessage(SSH_AGENT_IDENTITIES_ANSWER, answer.getCompactData());
                break;
            case SSH_AGENTC_SIGN_REQUEST:
                signRequest(contents);
                break;
            default:
                writeMessage(SSH_AGENT_FAILURE, new byte[0]);
        }
    }

    private void signRequest(byte[] contents) throws IOException {
        try {
            Buffer.PlainBuffer request = new Buffer.PlainBuffer(contents);
            byte[] keyBlob = request.readBytes();
            byte[] data = request.readBytes();
            request.readUInt32(); // flags, ignored by this fake (no RSA-SHA2)

            Identity identity = findIdentity(keyBlob);
            if (identity == null) {
                writeMessage(SSH_AGENT_FAILURE, new byte[0]);
                return;
            }
            identity.signature.initSign(identity.privateKey);
            identity.signature.update(data);
            byte[] signatureValue = new Buffer.PlainBuffer()
                    .putString(identity.signature.getSignatureName())
                    .putBytes(identity.signature.encode(identity.signature.sign()))
                    .getCompactData();
            writeMessage(SSH_AGENT_SIGN_RESPONSE, new Buffer.PlainBuffer().putBytes(signatureValue).getCompactData());
        } catch (Buffer.BufferException e) {
            writeMessage(SSH_AGENT_FAILURE, new byte[0]);
        }
    }

    private Identity findIdentity(byte[] keyBlob) {
        for (Identity identity : identities) {
            if (java.util.Arrays.equals(identity.keyBlob, keyBlob)) {
                return identity;
            }
        }
        return null;
    }

    private void writeMessage(byte type, byte[] contents) throws IOException {
        int length = 1 + contents.length;
        agentOut.write(new byte[]{
                (byte) (length >>> 24), (byte) (length >>> 16), (byte) (length >>> 8), (byte) length, type
        });
        agentOut.write(contents);
        agentOut.flush();
    }

    private static Signature signatureFor(KeyType keyType) {
        for (net.schmizz.sshj.common.Factory.Named<com.hierynomus.sshj.key.KeyAlgorithm> factory : new net.schmizz.sshj.DefaultConfig().getKeyAlgorithms()) {
            com.hierynomus.sshj.key.KeyAlgorithm keyAlgorithm = factory.create();
            if (keyAlgorithm.getKeyFormat() == keyType) {
                return keyAlgorithm.newSignature();
            }
        }
        throw new IllegalArgumentException("No signature available for key type " + keyType);
    }

    @Override
    public void close() throws IOException {
        try {
            clientIn.close();
            clientOut.close();
            agentOut.close();
            agentIn.close();
        } finally {
            thread.interrupt();
        }
    }
}
