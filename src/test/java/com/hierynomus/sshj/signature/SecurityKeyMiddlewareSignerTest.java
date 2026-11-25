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
package com.hierynomus.sshj.signature;

import com.hierynomus.sshj.userauth.fido.SecurityKeyPrivateKey;
import com.hierynomus.sshj.userauth.fido.SecurityKeyPublicKey;
import com.hierynomus.sshj.userauth.fido.SecurityKeySigner;
import com.hierynomus.sshj.userauth.fido.SecurityKeyTestSigners;
import com.hierynomus.sshj.userauth.fido.SoftwareSecurityKeyMiddleware;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Signs through the {@code SecurityKeySigner} SPI the way an application using an OpenSSH security key
 * middleware ({@code libsk-libfido2}, {@code ssh-keychain.dylib}) would, with a
 * {@link SoftwareSecurityKeyMiddleware} standing in for the hardware: it takes the message and derives
 * the client-data hash itself, as {@code sk_sign()} does.
 * <p>
 * Regression test for #1068, where the signer was given only the hash, so a middleware signed the hash of
 * the hash and every server rejected the result.
 */
public class SecurityKeyMiddlewareSignerTest {

    private static final String APPLICATION = "ssh:";
    private static final byte FLAGS = 0x04; // as requested by the key; the "touch" adds user-presence
    private static final byte[] KEY_HANDLE = {5, 4, 3, 2, 1};
    private static final byte[] MESSAGE = "ssh data to sign: session id and userauth request".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void middlewareSignatureVerifies(boolean ed25519) throws Exception {
        final Token token = new Token(ed25519);

        final byte[] wireSignature = token.sign(SecurityKeyTestSigners.middlewareSigner(token.middleware, ed25519));

        assertTrue(token.verify(wireSignature), "a signature made by the middleware over the data should verify");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void wireSignatureCarriesTheFlagsAndCounterTheDeviceReported(boolean ed25519) throws Exception {
        final Token token = new Token(ed25519);

        final byte[] first = token.sign(SecurityKeyTestSigners.middlewareSigner(token.middleware, ed25519));
        final byte[] second = token.sign(SecurityKeyTestSigners.middlewareSigner(token.middleware, ed25519));

        assertEquals((byte) (FLAGS | SoftwareSecurityKeyMiddleware.USER_PRESENCE), flags(first));
        assertEquals(1L, counter(first));
        assertEquals(2L, counter(second), "the device counter advances on every signature");
        assertTrue(token.verify(first));
        assertTrue(token.verify(second));
    }

    /** What happened before #1068: forwarding the challenge to a middleware makes it hash a second time. */
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void forwardingTheChallengeToAMiddlewareDoesNotVerify(boolean ed25519) throws Exception {
        final Token token = new Token(ed25519);

        final byte[] wireSignature = token.sign(SecurityKeyTestSigners.challengeForwardingSigner(token.middleware, ed25519));

        assertFalse(token.verify(wireSignature), "the device signed SHA256(SHA256(data)), which must not verify");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void deviceRefusesAKeyHandleItDoesNotHold(boolean ed25519) throws Exception {
        final Token token = new Token(ed25519);
        final SecurityKeyPrivateKey otherCredential = new SecurityKeyPrivateKey(token.keyType.toString(), token.publicKey, FLAGS,
                new byte[] {9, 9, 9}, SecurityKeyTestSigners.middlewareSigner(token.middleware, ed25519));
        final Signature signature = token.newSignature();
        signature.initSign(otherCredential);
        signature.update(MESSAGE);

        org.junit.jupiter.api.Assertions.assertThrows(net.schmizz.sshj.common.SSHRuntimeException.class, signature::sign);
    }

    private static byte flags(byte[] wireSignature) throws Buffer.BufferException {
        final Buffer.PlainBuffer buf = new Buffer.PlainBuffer(wireSignature);
        buf.readBytes(); // key type
        buf.readBytes(); // raw signature
        return buf.readByte();
    }

    private static long counter(byte[] wireSignature) throws Buffer.BufferException {
        final Buffer.PlainBuffer buf = new Buffer.PlainBuffer(wireSignature);
        buf.readBytes(); // key type
        buf.readBytes(); // raw signature
        buf.readByte();  // flags
        return buf.readUInt32();
    }

    /** A software security key, with the credential, the public key and the middleware that drives it. */
    private static final class Token {
        final boolean ed25519;
        final KeyType keyType;
        final SecurityKeyPublicKey publicKey;
        final SoftwareSecurityKeyMiddleware middleware;

        Token(boolean ed25519) throws Exception {
            this.ed25519 = ed25519;
            this.keyType = ed25519 ? KeyType.SK_ED25519 : KeyType.SK_ECDSA;
            final KeyPair credential;
            if (ed25519) {
                credential = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            } else {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                credential = kpg.generateKeyPair();
            }
            this.publicKey = new SecurityKeyPublicKey((PublicKey) credential.getPublic(), APPLICATION);
            this.middleware = new SoftwareSecurityKeyMiddleware(ed25519, credential, KEY_HANDLE);
        }

        Signature newSignature() {
            return ed25519 ? new SignatureSkEd25519() : new SignatureSkEcdsa();
        }

        /** Signs {@link #MESSAGE} through sshj's signing path, as the auth layer does. */
        byte[] sign(SecurityKeySigner signer) {
            final SecurityKeyPrivateKey privateKey = new SecurityKeyPrivateKey(keyType.toString(), publicKey, FLAGS, KEY_HANDLE, signer);
            final Signature signature = newSignature();
            signature.initSign(privateKey);
            signature.update(MESSAGE);
            return signature.encode(signature.sign());
        }

        boolean verify(byte[] wireSignature) {
            final Signature verifier = newSignature();
            verifier.initVerify(publicKey);
            verifier.update(MESSAGE);
            return verifier.verify(wireSignature);
        }
    }
}
