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
package com.hierynomus.sshj.userauth.fido;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;

/**
 * A software stand-in for an OpenSSH security key <em>middleware</em> (the {@code sk-api} that
 * {@code libsk-libfido2} and {@code ssh-keychain.dylib} implement), so tests can exercise the signing
 * path as it behaves with real hardware, without any.
 * <p>
 * It follows the contract of {@code sk_sign()}:
 * <ul>
 *   <li>it takes the <em>message</em> and derives the client-data hash from it itself
 *       ({@code SHA256(message)}); handing it an already hashed challenge makes it sign the hash of the
 *       hash, exactly as the real thing does;</li>
 *   <li>the device signs {@code SHA256(application) || flags || counter || SHA256(message)};</li>
 *   <li>it only signs for the credential it holds, selected by the key handle;</li>
 *   <li>it reports the flags and counter it used. It sets the user-presence flag, as a touch would, and
 *       increments the counter on every signature, starting at 1;</li>
 *   <li>the response carries an ECDSA signature as separate big-endian {@code r} and {@code s} values
 *       ({@code sig_r}, {@code sig_s}), and an Ed25519 signature whole in {@code sig_r}.</li>
 * </ul>
 */
public final class SoftwareSecurityKeyMiddleware {

    /** {@code SSH_SK_USER_PRESENCE_REQD}: the flag a touch on the device sets. */
    public static final byte USER_PRESENCE = 0x01;

    /** The middleware's answer: what {@code struct sk_sign_response} carries. */
    public static final class Response {
        private final byte flags;
        private final long counter;
        private final byte[] sigR;
        private final byte[] sigS;

        Response(byte flags, long counter, byte[] sigR, byte[] sigS) {
            this.flags = flags;
            this.counter = counter;
            this.sigR = sigR;
            this.sigS = sigS;
        }

        public byte getFlags() {
            return flags;
        }

        public long getCounter() {
            return counter;
        }

        /** The ECDSA {@code r} (unsigned, big-endian), or the whole Ed25519 signature. */
        public byte[] getSigR() {
            return sigR.clone();
        }

        /** The ECDSA {@code s} (unsigned, big-endian); empty for Ed25519. */
        public byte[] getSigS() {
            return sigS.clone();
        }
    }

    private final boolean ed25519;
    private final KeyPair credential;
    private final byte[] keyHandle;
    private long counter;

    /**
     * @param ed25519   whether the credential is an Ed25519 key; otherwise a NIST P-256 ECDSA key
     * @param credential the credential held by the device
     * @param keyHandle the handle that selects that credential
     */
    public SoftwareSecurityKeyMiddleware(boolean ed25519, KeyPair credential, byte[] keyHandle) {
        this.ed25519 = ed25519;
        this.credential = credential;
        this.keyHandle = keyHandle.clone();
    }

    /**
     * The equivalent of {@code sk_sign()}.
     *
     * @param message     the message to sign; the client-data hash is derived from it here
     * @param application the application string, e.g. {@code "ssh:"}
     * @param keyHandle   the handle of the credential to sign with
     * @param flags       the flags requested by the key
     * @throws IOException if the key handle is not one the device holds
     */
    public synchronized Response sign(byte[] message, String application, byte[] keyHandle, byte flags) throws IOException {
        if (!Arrays.equals(this.keyHandle, keyHandle)) {
            throw new IOException("key handle does not belong to this device");
        }
        final byte returnedFlags = (byte) (flags | USER_PRESENCE);
        final long returnedCounter = ++counter;
        try {
            final byte[] signedData = concat(
                    sha256(application.getBytes(StandardCharsets.UTF_8)),
                    new byte[] {returnedFlags},
                    new byte[] {
                            (byte) (returnedCounter >>> 24), (byte) (returnedCounter >>> 16),
                            (byte) (returnedCounter >>> 8), (byte) returnedCounter},
                    sha256(message));
            if (ed25519) {
                final Signature signature = Signature.getInstance("Ed25519");
                signature.initSign(credential.getPrivate());
                signature.update(signedData);
                return new Response(returnedFlags, returnedCounter, signature.sign(), new byte[0]);
            }
            // IEEE P1363 gives r || s as two fixed-width values, i.e. what a middleware reports separately.
            final Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
            signature.initSign(credential.getPrivate());
            signature.update(signedData);
            final byte[] rs = signature.sign();
            final int half = rs.length / 2;
            return new Response(returnedFlags, returnedCounter,
                    unsigned(new BigInteger(1, Arrays.copyOfRange(rs, 0, half))),
                    unsigned(new BigInteger(1, Arrays.copyOfRange(rs, half, rs.length))));
        } catch (GeneralSecurityException e) {
            throw new IOException("software authenticator failed", e);
        }
    }

    /** Minimal big-endian unsigned encoding, without the sign byte {@link BigInteger#toByteArray()} adds. */
    private static byte[] unsigned(BigInteger value) {
        final byte[] bytes = value.toByteArray();
        return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static byte[] sha256(byte[] data) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        final byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }
}
