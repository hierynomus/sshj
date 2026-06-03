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
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.KeyType;
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

    @Test
    public void authenticatesWithSkEcdsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        authenticatesWith(kpg.generateKeyPair(), KeyType.SK_ECDSA, "SHA256withECDSA");
    }

    @Test
    public void authenticatesWithSkEd25519() throws Exception {
        authenticatesWith(KeyPairGenerator.getInstance("Ed25519").generateKeyPair(), KeyType.SK_ED25519, "Ed25519");
    }

    private void authenticatesWith(KeyPair keyPair, KeyType keyType, String jcaAlgorithm) throws Exception {
        SecurityKeyPublicKey publicKey = new SecurityKeyPublicKey(keyPair.getPublic(), APPLICATION);
        SecurityKeySigner signer = softwareAuthenticator(keyPair.getPrivate(), jcaAlgorithm);
        SecurityKeyPrivateKey privateKey = new SecurityKeyPrivateKey(keyType.toString(), publicKey, FLAGS, new byte[]{1, 2, 3, 4}, signer);

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
