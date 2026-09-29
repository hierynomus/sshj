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

import com.hierynomus.sshj.userauth.certificate.Certificate;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.SHA256;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

/**
 * Post-Quantum Traditional (PQ/T) hybrid SSH key exchange combining
 * {@code curve25519-sha256} with {@code ML-KEM-768}, as defined in the IETF
 * draft <em>draft-kampanakis-curdle-ssh-pq-ke</em> and implemented by
 * OpenSSH&nbsp;9.9+ under the algorithm name {@code mlkem768x25519-sha256}.
 *
 * <p>Wire protocol (the message numbers 30/31 are reused from RFC&nbsp;4253):</p>
 * <pre>
 * client -&gt; server: SSH_MSG_KEX_HYBRID_INIT (30)
 *   string  C_INIT = C_PK2 || C_PK1
 * server -&gt; client: SSH_MSG_KEX_HYBRID_REPLY (31)
 *   string  K_S, server's public host key
 *   string  S_REPLY = S_CT2 || S_PK1
 *   string  signature on the exchange hash
 * </pre>
 *
 * <p>Where {@code C_PK1} / {@code S_PK1} are 32-byte X25519 public keys and
 * {@code C_PK2} / {@code S_CT2} are the ML-KEM-768 client public key
 * ({@value MLKEM768#PUBLIC_KEY_LENGTH} bytes) and server ciphertext
 * ({@value MLKEM768#CIPHERTEXT_LENGTH} bytes) respectively.</p>
 *
 * <p>The shared secret K is computed as {@code K = SHA-256(K_PQ || K_CL)} and
 * is encoded as an SSH {@code string} (not {@code mpint}) when fed into both
 * the exchange hash H and the session key derivation.</p>
 */
public class MLKEM768X25519SHA256 extends KeyExchangeBase {

    private static final String NAME = "mlkem768x25519-sha256";

    /**
     * Whether this hybrid key exchange can be used at runtime. Requires a JCA provider
     * that supplies an {@code ML-KEM-768} {@link java.security.KeyPairGenerator} and
     * {@link java.security.KeyFactory}, plus one of:
     * <ul>
     *   <li>the JDK&nbsp;21+ {@code javax.crypto.KEM} API together with a provider that
     *       registers an {@code ML-KEM} KEM service, or</li>
     *   <li>the Bouncy Castle PQC lightweight API
     *       ({@code org.bouncycastle.pqc.crypto.mlkem}) on the classpath, which works
     *       on any JDK.</li>
     * </ul>
     * When neither is reachable callers should refrain from advertising the algorithm.
     *
     * @return {@code true} iff a working ML-KEM-768 implementation is reachable
     */
    public static boolean isSupported() {
        return SecurityUtils.isAlgorithmAvailable("KeyPairGenerator", MLKEM768.KEY_ALGORITHM)
                && SecurityUtils.isAlgorithmAvailable("KeyFactory", MLKEM768.KEY_ALGORITHM)
                && SecurityUtils.isAlgorithmAvailable("KEM", MLKEM768.KEM_ALGORITHM);
    }

    /** Named factory for the {@code mlkem768x25519-sha256} key exchange. */
    public static class Factory implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {
        @Override
        public KeyExchange create() {
            if (!isSupported()) {
                throw new IllegalStateException(
                        "mlkem768x25519-sha256 is not supported on this runtime: requires a JCA "
                                + "provider for ML-KEM-768 plus either Java 21+ (javax.crypto.KEM) "
                                + "or Bouncy Castle PQC on the classpath");
            }
            return new MLKEM768X25519SHA256();
        }

        @Override
        public String getName() {
            return NAME;
        }
    }

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final MLKEM768 mlkem = new MLKEM768();
    private final Curve25519DH x25519 = new Curve25519DH();

    private byte[] cInit;

    private byte[] kEncoded;

    public MLKEM768X25519SHA256() {
        super(new SHA256());
    }

    @Override
    public void init(final Transport trans, final String V_S, final String V_C, final byte[] I_S, final byte[] I_C)
            throws GeneralSecurityException, TransportException {
        super.init(trans, V_S, V_C, I_S, I_C);
        digest.init();

        // Generate X25519 ephemeral key pair (C_PK1).
        x25519.init(null, trans.getConfig().getRandomFactory());

        // Generate ML-KEM-768 ephemeral key pair (C_PK2) via JCA.
        final byte[] mlkemPublicKey = mlkem.generateKeyPair();

        // C_INIT is the concatenation C_PK2 || C_PK1.
        final byte[] x25519PublicKey = x25519.getE();
        cInit = new byte[MLKEM768.PUBLIC_KEY_LENGTH + Curve25519DH.KEY_LENGTH];
        System.arraycopy(mlkemPublicKey, 0, cInit, 0, MLKEM768.PUBLIC_KEY_LENGTH);
        System.arraycopy(x25519PublicKey, 0, cInit, MLKEM768.PUBLIC_KEY_LENGTH, Curve25519DH.KEY_LENGTH);

        log.debug("Sending SSH_MSG_KEX_HYBRID_INIT");
        trans.write(new SSHPacket(Message.KEXDH_INIT).putBytes(cInit));
    }

    @Override
    public boolean next(final Message msg, final SSHPacket packet)
            throws GeneralSecurityException, TransportException {
        if (msg != Message.KEXDH_31) {
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                    "Unexpected packet: " + msg);
        }

        log.debug("Received SSH_MSG_KEX_HYBRID_REPLY");
        final byte[] K_S;
        final byte[] sReply;
        final byte[] sig;
        try {
            K_S = packet.readBytes();
            sReply = packet.readBytes();
            sig = packet.readBytes();
            hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }

        // S_REPLY = S_CT2 || S_PK1
        final int expectedLength = MLKEM768.CIPHERTEXT_LENGTH + Curve25519DH.KEY_LENGTH;
        if (sReply.length != expectedLength) {
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                    "S_REPLY length must be " + expectedLength + " bytes but was " + sReply.length);
        }
        final byte[] sCt2 = new byte[MLKEM768.CIPHERTEXT_LENGTH];
        final byte[] sPk1 = new byte[Curve25519DH.KEY_LENGTH];
        System.arraycopy(sReply, 0, sCt2, 0, MLKEM768.CIPHERTEXT_LENGTH);
        System.arraycopy(sReply, MLKEM768.CIPHERTEXT_LENGTH, sPk1, 0, Curve25519DH.KEY_LENGTH);

        // K_PQ: decapsulate ML-KEM-768 ciphertext.
        final byte[] kPq = mlkem.decapsulate(sCt2);

        // K_CL: X25519 shared secret in raw byte form (NOT mpint), as required by the draft.
        x25519.computeK(sPk1);
        final byte[] kCl = x25519.getSharedSecretBytes();

        // Per RFC 8731, an all-zero output indicates a low-order point and MUST be rejected.
        if (isAllZero(kCl)) {
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                    "X25519 key agreement produced an all-zero shared secret");
        }

        // K = HASH(K_PQ || K_CL), encoded as a string in H and key derivation.
        digest.init();
        digest.update(kPq, 0, kPq.length);
        digest.update(kCl, 0, kCl.length);
        kEncoded = digest.digest();

        // Compute exchange hash H over: V_C, V_S, I_C, I_S, K_S, C_INIT, S_REPLY, K (as string).
        final Buffer.PlainBuffer hashBuffer = initializedBuffer()
                .putString(K_S)
                .putString(cInit)
                .putString(sReply)
                .putString(kEncoded);

        digest.init();
        digest.update(hashBuffer.array(), hashBuffer.rpos(), hashBuffer.available());
        H = digest.digest();

        // Verify the host key signature on H.
        final Signature signature = trans.getHostKeyAlgorithm().newSignature();
        if (hostKey instanceof Certificate<?>) {
            signature.initVerify(((Certificate<?>) hostKey).getKey());
        } else {
            signature.initVerify(hostKey);
        }
        signature.update(H, 0, H.length);
        if (!signature.verify(sig)) {
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                    "KeyExchange signature verification failed");
        }

        KexHostKeyCertificateVerifier.verify(trans, hostKey, K_S);

        return true;
    }

    /**
     * For PQ/T hybrid key exchanges, K is the SHA-256 output of the concatenation of
     * the two shared secrets and is encoded as an SSH {@code string} (length-prefixed
     * byte array) per draft-kampanakis-curdle-ssh-pq-ke section&nbsp;2.5, instead of
     * the traditional {@code mpint} encoding used by RFC&nbsp;4253 / RFC&nbsp;5656 /
     * RFC&nbsp;8731 key exchanges.
     */
    @Override
    public void putSharedSecret(final Buffer.PlainBuffer buffer) {
        buffer.putString(kEncoded);
    }

    /**
     * Unsupported for the hybrid PQ key exchange. K is a fixed-length byte string
     * (the SHA-256 of {@code K_PQ || K_CL}) and is encoded on the wire as an SSH
     * {@code string}, not as an {@code mpint}. Callers that legitimately need the
     * shared secret bytes for inclusion in the exchange hash or key derivation
     * MUST use {@link #putSharedSecret(Buffer.PlainBuffer)}.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public BigInteger getK() {
        throw new UnsupportedOperationException(
                "K is a fixed-length string for hybrid KEX; use putSharedSecret(...)");
    }

    private static boolean isAllZero(final byte[] data) {
        int acc = 0;
        for (final byte b : data) {
            acc |= b & 0xff;
        }
        return acc == 0;
    }
}
