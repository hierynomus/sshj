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

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Verifies that the {@code sk-ecdsa-sha2-nistp256@openssh.com} and {@code sk-ssh-ed25519@openssh.com}
 * public key blobs are written and read back exactly per OpenSSH PROTOCOL.u2f.
 */
public class SecurityKeyPublicKeyTest {

    private static final String APPLICATION = "ssh:";

    @Test
    public void skEcdsaIsRecognizedByType() {
        assertEquals(KeyType.SK_ECDSA, KeyType.fromString("sk-ecdsa-sha2-nistp256@openssh.com"));
        assertEquals(KeyType.SK_ED25519, KeyType.fromString("sk-ssh-ed25519@openssh.com"));
    }

    @Test
    public void skEcdsaRoundTrips() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        SecurityKeyPublicKey key = new SecurityKeyPublicKey(kp.getPublic(), APPLICATION);
        assertEquals(KeyType.SK_ECDSA, KeyType.fromKey(key));

        byte[] blob = new Buffer.PlainBuffer().putPublicKey(key).getCompactData();

        // Structure per PROTOCOL.u2f: string type, string curve, string Q, string application
        Buffer.PlainBuffer reader = new Buffer.PlainBuffer(blob);
        assertEquals("sk-ecdsa-sha2-nistp256@openssh.com", reader.readString());
        assertEquals("nistp256", reader.readString());
        reader.readBytes(); // Q
        assertEquals(APPLICATION, reader.readString());

        // Round trip
        PublicKey parsed = new Buffer.PlainBuffer(blob).readPublicKey();
        SecurityKeyPublicKey parsedSk = assertInstanceOf(SecurityKeyPublicKey.class, parsed);
        assertEquals(APPLICATION, parsedSk.getApplication());
        assertEquals(KeyType.SK_ECDSA, KeyType.fromKey(parsed));
        assertArrayEquals(blob, new Buffer.PlainBuffer().putPublicKey(parsed).getCompactData());
    }

    @Test
    public void skEd25519RoundTrips() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        SecurityKeyPublicKey key = new SecurityKeyPublicKey(kp.getPublic(), APPLICATION);
        assertEquals(KeyType.SK_ED25519, KeyType.fromKey(key));

        byte[] blob = new Buffer.PlainBuffer().putPublicKey(key).getCompactData();

        // Structure per PROTOCOL.u2f: string type, string publicKey, string application
        Buffer.PlainBuffer reader = new Buffer.PlainBuffer(blob);
        assertEquals("sk-ssh-ed25519@openssh.com", reader.readString());
        assertEquals(32, reader.readBytes().length); // raw Ed25519 public key
        assertEquals(APPLICATION, reader.readString());

        // Round trip
        PublicKey parsed = new Buffer.PlainBuffer(blob).readPublicKey();
        SecurityKeyPublicKey parsedSk = assertInstanceOf(SecurityKeyPublicKey.class, parsed);
        assertEquals(APPLICATION, parsedSk.getApplication());
        assertEquals(KeyType.SK_ED25519, KeyType.fromKey(parsed));
        assertArrayEquals(blob, new Buffer.PlainBuffer().putPublicKey(parsed).getCompactData());
    }

    @Test
    public void nonAsciiApplicationRoundTrips() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String application = "ssh:??-key"; // exercise UTF-8 length vs char count

        SecurityKeyPublicKey key = new SecurityKeyPublicKey(kp.getPublic(), application);
        byte[] blob = new Buffer.PlainBuffer().putPublicKey(key).getCompactData();
        PublicKey parsed = new Buffer.PlainBuffer(blob).readPublicKey();

        assertEquals(application, ((SecurityKeyPublicKey) parsed).getApplication());
    }
}
