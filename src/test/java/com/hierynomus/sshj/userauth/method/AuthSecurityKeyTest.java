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
import com.hierynomus.sshj.userauth.fido.SecurityKeyPrivateKey;
import com.hierynomus.sshj.userauth.fido.SecurityKeyPublicKey;
import com.hierynomus.sshj.userauth.fido.SecurityKeySignatureData;
import com.hierynomus.sshj.userauth.fido.SecurityKeySigner;
import com.hierynomus.sshj.userauth.fido.SecurityKeyTestSigners;
import com.hierynomus.sshj.userauth.fido.SoftwareSecurityKeyMiddleware;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Authenticates to a real (in-process Apache MINA) SSH server using the {@code publickey} method
 * with a {@link SecurityKeyPrivateKey}, i.e. through the {@link SecurityKeySigner} SPI rather than an
 * agent. A software authenticator stands in for the YubiKey. This proves the non-agent SPI path
 * works end-to-end and that the FIDO signature framing in the auth layer is accepted by an
 * independent server.
 */
public class AuthSecurityKeyTest {

    private static final String APPLICATION = "ssh:";
    private static final byte FLAGS = 0x01;
    private static final long COUNTER = 7L;

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension(false);

    @BeforeEach
    public void setUp() throws IOException {
        fixture.getServer().setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        fixture.getServer().start();
    }

    // Only sk-ecdsa is exercised end-to-end here. The in-process MINA server verifies sk-ssh-ed25519
    // through net.i2p.crypto.eddsa, which sshj does not depend on. The auth-layer signature framing is
    // identical for both key types, and sk-ssh-ed25519 sign/verify is covered by SecurityKeySignatureTest.
    @Test
    public void authenticatesWithSkEcdsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        authenticatesWith(kpg.generateKeyPair(), KeyType.SK_ECDSA, "SHA256withECDSA");
    }

    /**
     * The same, with the authenticator driven the way an OpenSSH security key middleware is: handed the
     * message to sign, which it hashes itself (#1068). The server must accept what its device signed.
     */
    @Test
    public void authenticatesWithSkEcdsaThroughAMiddleware() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] keyHandle = {1, 2, 3, 4};
        SoftwareSecurityKeyMiddleware middleware = new SoftwareSecurityKeyMiddleware(false, keyPair, keyHandle);

        authenticatesWith(keyPair, KeyType.SK_ECDSA, SecurityKeyTestSigners.middlewareSigner(middleware, false), keyHandle);
    }

    /**
     * A signer that fails, like a user cancelling the touch or PIN prompt, must only fail the publickey attempt.
     * The connection has to stay open so the caller can fall back to another method (it used to be closed).
     */
    @Test
    public void failingSignerFailsTheAttemptButKeepsTheConnectionOpen() throws Exception {
        IOException cancelled = new IOException("user cancelled the touch prompt");
        SSHClient client = fixture.setupConnectedDefaultClient();

        UserAuthException e = assertThrows(UserAuthException.class,
                () -> client.auth("test", new AuthPublickey(securityKeyProvider(request -> {
                    throw cancelled;
                }))));

        assertFalse(client.isAuthenticated());
        assertTrue(client.isConnected(), "the connection must survive a failed security key signature");
        assertTrue(hasCause(e, cancelled), "the signer's exception should be preserved as the cause");

        client.authPassword("test", "test");
        assertTrue(client.isAuthenticated(), "should be able to fall back to another method on the same connection");
    }

    @Test
    public void securityKeyWithoutSignerFailsTheAttemptButKeepsTheConnectionOpen() throws Exception {
        SSHClient client = fixture.setupConnectedDefaultClient();

        assertThrows(UserAuthException.class, () -> client.auth("test", new AuthPublickey(securityKeyProvider(null))));

        assertTrue(client.isConnected());
        client.authPassword("test", "test");
        assertTrue(client.isAuthenticated());
    }

    private static boolean hasCause(Throwable t, Throwable expected) {
        for (; t != null; t = t.getCause()) {
            if (t == expected) {
                return true;
            }
        }
        return false;
    }

    private static KeyProvider securityKeyProvider(SecurityKeySigner signer) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();
        SecurityKeyPublicKey publicKey = new SecurityKeyPublicKey(keyPair.getPublic(), APPLICATION);
        SecurityKeyPrivateKey privateKey = new SecurityKeyPrivateKey(KeyType.SK_ECDSA.toString(), publicKey, FLAGS,
                new byte[]{1, 2, 3, 4}, signer);
        return new KeyProvider() {
            @Override
            public PrivateKey getPrivate() {
                return privateKey;
            }

            @Override
            public PublicKey getPublic() {
                return publicKey;
            }

            @Override
            public KeyType getType() {
                return KeyType.SK_ECDSA;
            }
        };
    }

    private void authenticatesWith(KeyPair keyPair, KeyType keyType, String jcaAlgorithm) throws Exception {
        authenticatesWith(keyPair, keyType, softwareAuthenticator(keyPair.getPrivate(), jcaAlgorithm), new byte[]{1, 2, 3, 4});
    }

    private void authenticatesWith(KeyPair keyPair, KeyType keyType, SecurityKeySigner signer, byte[] keyHandle) throws Exception {
        SecurityKeyPublicKey publicKey = new SecurityKeyPublicKey(keyPair.getPublic(), APPLICATION);
        SecurityKeyPrivateKey privateKey = new SecurityKeyPrivateKey(keyType.toString(), publicKey, FLAGS, keyHandle, signer);

        KeyProvider keyProvider = new KeyProvider() {
            @Override
            public PrivateKey getPrivate() {
                return privateKey;
            }

            @Override
            public PublicKey getPublic() {
                return publicKey;
            }

            @Override
            public KeyType getType() {
                return keyType;
            }
        };

        SSHClient client = fixture.setupConnectedDefaultClient();
        client.auth("jeroen", new AuthPublickey(keyProvider));
        assertTrue(client.isAuthenticated(), "client should authenticate with a security key via the SPI");
    }

    private static SecurityKeySigner softwareAuthenticator(PrivateKey credentialKey, String jcaAlgorithm) {
        return request -> {
            byte[] rpIdHash = sha256(request.getApplication().getBytes(StandardCharsets.UTF_8));
            byte[] authenticatorData = new byte[rpIdHash.length + 5];
            System.arraycopy(rpIdHash, 0, authenticatorData, 0, rpIdHash.length);
            authenticatorData[rpIdHash.length] = FLAGS;
            authenticatorData[rpIdHash.length + 1] = (byte) ((COUNTER >>> 24) & 0xff);
            authenticatorData[rpIdHash.length + 2] = (byte) ((COUNTER >>> 16) & 0xff);
            authenticatorData[rpIdHash.length + 3] = (byte) ((COUNTER >>> 8) & 0xff);
            authenticatorData[rpIdHash.length + 4] = (byte) (COUNTER & 0xff);

            byte[] signed = new byte[authenticatorData.length + request.getChallenge().length];
            System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
            System.arraycopy(request.getChallenge(), 0, signed, authenticatorData.length, request.getChallenge().length);

            try {
                java.security.Signature s = java.security.Signature.getInstance(jcaAlgorithm);
                s.initSign(credentialKey);
                s.update(signed);
                return new SecurityKeySignatureData(FLAGS, COUNTER, s.sign());
            } catch (Exception e) {
                throw new IOException("software authenticator failed", e);
            }
        };
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
