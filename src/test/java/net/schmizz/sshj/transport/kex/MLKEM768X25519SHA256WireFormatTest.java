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

import com.hierynomus.sshj.key.KeyAlgorithm;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.SshjKEM;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.digest.SHA256;
import net.schmizz.sshj.transport.random.JCERandom;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Targeted wire-format assertions for {@link MLKEM768X25519SHA256} that don't depend on
 * a peer SSH implementation. These verify the byte layout mandated by
 * {@code draft-kampanakis-curdle-ssh-pq-ke-05}, in particular invariants that an
 * interop test against a peer with the same bug would fail to catch.
 */
public class MLKEM768X25519SHA256WireFormatTest {

    /**
     * {@code C_INIT = C_PK2 || C_PK1} where {@code C_PK2} is the 1184-byte ML-KEM-768 public
     * key and {@code C_PK1} is the 32-byte X25519 public key, in that order. Asserts the
     * exact concatenation length and that the leading 1184 bytes round-trip as a valid
     * ML-KEM-768 public key by encapsulating against them.
     */
    @Test
    public void cInitIsMlkemPublicKeyConcatenatedWithX25519PublicKey() throws Exception {
        final SSHPacket initPacket = runInitAndCapturePacket();

        // First byte: SSH_MSG_KEX_HYBRID_INIT = 30.
        assertEquals(Message.KEXDH_INIT, initPacket.readMessageID());
        // Then: C_INIT as an SSH 'string' (uint32 length || bytes).
        final byte[] cInit = initPacket.readBytes();

        assertEquals(MLKEM768.PUBLIC_KEY_LENGTH + Curve25519DH.KEY_LENGTH, cInit.length,
                "C_INIT must be exactly PUBLIC_KEY_LENGTH + KEY_LENGTH bytes");

        // Demonstrate the leading slice is a valid ML-KEM-768 public key by encapsulating
        // against it; this would fail if the order were reversed (X25519 key first).
        final byte[] mlkemPk = new byte[MLKEM768.PUBLIC_KEY_LENGTH];
        System.arraycopy(cInit, 0, mlkemPk, 0, MLKEM768.PUBLIC_KEY_LENGTH);
        final SshjKEM.Encapsulated enc = MLKEM768.encapsulate(mlkemPk);
        assertEquals(MLKEM768.CIPHERTEXT_LENGTH, enc.getCiphertext().length);
    }

    /**
     * Per draft-kampanakis section 2.4: {@code K = HASH(K_PQ || K_CL)}, with the PQ secret
     * first. Reversing the order changes K and silently breaks interop. We control both
     * halves by playing the server.
     */
    @Test
    public void kIsSha256OfMlkemSecretConcatenatedWithX25519Secret() throws Exception {
        final ServerExchange exchange = runFullExchange();

        // Recompute K with the documented order.
        final SHA256 hash = new SHA256();
        hash.init();
        hash.update(exchange.kPq, 0, exchange.kPq.length);
        hash.update(exchange.kCl, 0, exchange.kCl.length);
        final byte[] expectedK = hash.digest();

        // And with the wrong order, to make sure the assertion below would fail if the
        // implementation accidentally reversed the inputs.
        hash.init();
        hash.update(exchange.kCl, 0, exchange.kCl.length);
        hash.update(exchange.kPq, 0, exchange.kPq.length);
        final byte[] reversedK = hash.digest();

        assertArrayEquals(expectedK, exchange.kEncoded,
                "K must be SHA-256(K_PQ || K_CL) in that exact order");
        assertNotEquals(new BigInteger(1, reversedK), new BigInteger(1, exchange.kEncoded),
                "test setup sanity: reversed-order K must differ from documented-order K");
    }

    /**
     * Per draft-kampanakis section 2.5: K is encoded as an SSH {@code string} (length-prefixed
     * fixed byte array) — NOT as an {@code mpint}. The discriminator: when K's high bit is
     * set, {@code mpint} would prepend a 0x00 sign byte, expanding the length to 33; the
     * draft mandates exactly 32 bytes with no padding.
     *
     * <p>We force the high-bit case by retrying until SHA-256 returns a value whose first
     * byte has the high bit set; with random K_PQ/K_CL inputs each attempt has ≈50%
     * probability so we converge in a few iterations.</p>
     */
    @Test
    public void putSharedSecretWritesStringNotMpintEvenWhenHighBitSet() throws Exception {
        ServerExchange exchange = null;
        for (int attempt = 0; attempt < 32; attempt++) {
            final ServerExchange candidate = runFullExchange();
            if ((candidate.kEncoded[0] & 0x80) != 0) {
                exchange = candidate;
                break;
            }
        }
        assertTrue(exchange != null,
                "could not produce a K with the high bit set in 32 attempts (extremely unlikely)");

        // putSharedSecret() must emit: 4-byte big-endian length == 32, then the 32 K bytes.
        // mpint encoding of the same value would emit length == 33 with a leading 0x00.
        final Buffer.PlainBuffer buf = new Buffer.PlainBuffer();
        exchange.kex.putSharedSecret(buf);
        final byte[] wire = buf.getCompactData();

        assertEquals(4 + 32, wire.length,
                "K must be a 32-byte SSH string (4-byte length + 32 bytes), not an mpint");
        final int length = ByteBuffer.wrap(wire, 0, 4).getInt();
        assertEquals(32, length, "string length prefix must be 32");
        final byte[] payload = new byte[32];
        System.arraycopy(wire, 4, payload, 0, 32);
        assertArrayEquals(exchange.kEncoded, payload,
                "string payload must be exactly the K bytes with no mpint sign-byte padding");

        // Cross-check against what an mpint would have produced.
        final Buffer.PlainBuffer mpintBuf = new Buffer.PlainBuffer();
        mpintBuf.putMPInt(new BigInteger(1, exchange.kEncoded));
        final int mpintLength = ByteBuffer.wrap(mpintBuf.getCompactData(), 0, 4).getInt();
        assertEquals(33, mpintLength,
                "test setup sanity: mpint encoding of a high-bit-set 32-byte value must be 33 bytes");
    }

    /**
     * For every other KEX in sshj K is a number and callers reasonably assume
     * {@code new Buffer.PlainBuffer().putMPInt(kex.getK())} reproduces the exact bytes
     * that went into the exchange hash H. For the hybrid PQ KEX that assumption is wrong:
     * K is a fixed-length string and is encoded via {@link KeyExchange#putSharedSecret}.
     * To prevent silent misuse, {@link MLKEM768X25519SHA256#getK()} must fail loudly.
     */
    @Test
    public void getKThrowsUnsupportedOperation() throws Exception {
        final ServerExchange exchange = runFullExchange();
        final UnsupportedOperationException ex = assertThrows(UnsupportedOperationException.class,
                () -> exchange.kex.getK());
        assertTrue(ex.getMessage() != null && ex.getMessage().contains("putSharedSecret"),
                "error message should steer callers toward putSharedSecret(...) but was: " + ex.getMessage());
    }

    /**
     * Drives {@link MLKEM768X25519SHA256#init} with mocked transport collaborators and
     * returns the {@link SSHPacket} the implementation wrote to the wire.
     */
    private SSHPacket runInitAndCapturePacket() throws Exception {
        final Transport trans = mock(Transport.class);
        final Config config = mock(Config.class);
        when(trans.getConfig()).thenReturn(config);
        when(config.getRandomFactory()).thenReturn(new JCERandom.Factory());

        final MLKEM768X25519SHA256 kex = new MLKEM768X25519SHA256();
        kex.init(trans, "SSH-2.0-server", "SSH-2.0-client", new byte[]{1}, new byte[]{2});

        final ArgumentCaptor<SSHPacket> packetCaptor = ArgumentCaptor.forClass(SSHPacket.class);
        verify(trans).write(packetCaptor.capture());
        return packetCaptor.getValue();
    }

    /**
     * Drives a complete {@code init} → server reply → {@code next} round trip, with this
     * test acting as the server. Returns the per-side secrets ({@code K_PQ}, {@code K_CL})
     * that the client must combine, plus the final {@code K} computed by the client.
     */
    private ServerExchange runFullExchange() throws Exception {
        // --- Set up a real Ed25519 host key for the signature step ---
        final KeyPairGenerator hostKpg = KeyPairGenerator.getInstance("Ed25519");
        final KeyPair hostKeyPair = hostKpg.generateKeyPair();
        final Buffer.PlainBuffer ksBuf = new Buffer.PlainBuffer();
        KeyType.ED25519.putPubKeyIntoBuffer(hostKeyPair.getPublic(), ksBuf);
        final byte[] kS = ksBuf.getCompactData();

        // --- Mock transport (signature.verify is stubbed to true; we don't need to actually sign) ---
        final Transport trans = mock(Transport.class);
        final Config config = mock(Config.class);
        when(trans.getConfig()).thenReturn(config);
        when(config.getRandomFactory()).thenReturn(new JCERandom.Factory());
        final KeyAlgorithm hostKeyAlg = mock(KeyAlgorithm.class);
        final Signature signature = mock(Signature.class);
        when(trans.getHostKeyAlgorithm()).thenReturn(hostKeyAlg);
        when(hostKeyAlg.newSignature()).thenReturn(signature);
        when(signature.verify(any(byte[].class))).thenReturn(true);

        // --- Drive init() and capture the packet the client emitted ---
        final MLKEM768X25519SHA256 kex = new MLKEM768X25519SHA256();
        kex.init(trans, "SSH-2.0-server", "SSH-2.0-client", new byte[]{1}, new byte[]{2});
        final ArgumentCaptor<SSHPacket> packetCaptor = ArgumentCaptor.forClass(SSHPacket.class);
        verify(trans).write(packetCaptor.capture());
        final SSHPacket initPacket = packetCaptor.getValue();
        initPacket.readMessageID();
        final byte[] cInit = initPacket.readBytes();

        // --- Server side: split C_INIT, encapsulate against C_PK2, agree against C_PK1 ---
        final byte[] cPk2 = new byte[MLKEM768.PUBLIC_KEY_LENGTH];
        final byte[] cPk1 = new byte[Curve25519DH.KEY_LENGTH];
        System.arraycopy(cInit, 0, cPk2, 0, MLKEM768.PUBLIC_KEY_LENGTH);
        System.arraycopy(cInit, MLKEM768.PUBLIC_KEY_LENGTH, cPk1, 0, Curve25519DH.KEY_LENGTH);

        final SshjKEM.Encapsulated enc = MLKEM768.encapsulate(cPk2);
        final byte[] kPq = enc.getSharedSecret();
        final byte[] sCt2 = enc.getCiphertext();

        final Curve25519DH serverDh = new Curve25519DH();
        serverDh.init(null, new JCERandom.Factory());
        serverDh.computeK(cPk1);
        final byte[] kCl = serverDh.getSharedSecretBytes();
        final byte[] sPk1 = serverDh.getE();

        final byte[] sReply = new byte[MLKEM768.CIPHERTEXT_LENGTH + Curve25519DH.KEY_LENGTH];
        System.arraycopy(sCt2, 0, sReply, 0, MLKEM768.CIPHERTEXT_LENGTH);
        System.arraycopy(sPk1, 0, sReply, MLKEM768.CIPHERTEXT_LENGTH, Curve25519DH.KEY_LENGTH);

        // --- Build the SSH_MSG_KEX_HYBRID_REPLY and feed it to next() ---
        final SSHPacket reply = new SSHPacket(Message.KEXDH_31)
                .putBytes(kS)
                .putBytes(sReply)
                .putBytes(new byte[]{0x00}); // signature payload; verify() is stubbed
        reply.readMessageID(); // advance past the message id, as the dispatcher would
        kex.next(Message.KEXDH_31, reply);

        // K is not retrievable as a BigInteger for the hybrid KEX (getK() throws);
        // extract the on-wire bytes via putSharedSecret(...), then strip the SSH string length prefix.
        final Buffer.PlainBuffer sharedSecretBuffer = new Buffer.PlainBuffer();
        kex.putSharedSecret(sharedSecretBuffer);
        final byte[] kEncoded;
        try {
            kEncoded = sharedSecretBuffer.readBytes();
        } catch (final Buffer.BufferException e) {
            throw new AssertionError("Failed to read K written by putSharedSecret", e);
        }

        return new ServerExchange(kex, kPq, kCl, kEncoded);
    }

    private static final class ServerExchange {
        final MLKEM768X25519SHA256 kex;
        final byte[] kPq;
        final byte[] kCl;
        final byte[] kEncoded;

        ServerExchange(final MLKEM768X25519SHA256 kex, final byte[] kPq, final byte[] kCl, final byte[] kEncoded) {
            this.kex = kex;
            this.kPq = kPq;
            this.kCl = kCl;
            this.kEncoded = kEncoded;
        }
    }
}
