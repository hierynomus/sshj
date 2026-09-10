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
package com.hierynomus.sshj.userauth.keyprovider;

import com.hierynomus.sshj.signature.SignatureSkEd25519;
import com.hierynomus.sshj.userauth.fido.SecurityKeyPrivateKey;
import com.hierynomus.sshj.userauth.fido.SecurityKeyPublicKey;
import com.hierynomus.sshj.userauth.fido.SecurityKeySignatureData;
import com.hierynomus.sshj.userauth.fido.SecurityKeySigner;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Loads a {@code sk-ssh-ed25519@openssh.com} key from a hand-built OpenSSH v1 key file (the
 * authenticator-resident format: application, flags, key handle, no private scalar) and checks that
 * the parsed key carries those fields and can sign once a {@link SecurityKeySigner} is attached.
 */
public class OpenSSHKeyV1SecurityKeyTest {

    private static final String APPLICATION = "ssh:";
    private static final byte FLAGS = 0x01;
    private static final byte[] KEY_HANDLE = {10, 20, 30, 40, 50};

    @Test
    public void loadsSkEd25519PrivateKey() throws Exception {
        KeyPair credential = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] rawPublicKey = rawEd25519PublicKey(credential.getPublic());
        String pem = buildOpenSshV1SkEd25519(rawPublicKey, APPLICATION, FLAGS, KEY_HANDLE, "sk-test@host");

        OpenSSHKeyV1KeyFile keyFile = new OpenSSHKeyV1KeyFile();
        keyFile.setSecurityKeySigner(softwareAuthenticator(credential.getPrivate()));
        keyFile.init(new StringReader(pem), null, null);

        PublicKey publicKey = keyFile.getPublic();
        SecurityKeyPublicKey skPublic = assertInstanceOf(SecurityKeyPublicKey.class, publicKey);
        assertEquals(APPLICATION, skPublic.getApplication());
        assertEquals(KeyType.SK_ED25519, keyFile.getType());

        PrivateKey privateKey = keyFile.getPrivate();
        SecurityKeyPrivateKey skPrivate = assertInstanceOf(SecurityKeyPrivateKey.class, privateKey);
        assertEquals(APPLICATION, skPrivate.getApplication());
        assertEquals(FLAGS, skPrivate.getFlags());
        assertArrayEquals(KEY_HANDLE, skPrivate.getKeyHandle());

        // The loaded key can sign, and the signature verifies against the public key.
        byte[] message = "loaded from openssh-key-v1".getBytes(StandardCharsets.UTF_8);
        Signature signing = new SignatureSkEd25519();
        signing.initSign(privateKey);
        signing.update(message);
        byte[] wireSignature = signing.encode(signing.sign());

        Signature verifying = new SignatureSkEd25519();
        verifying.initVerify(publicKey);
        verifying.update(message);
        assertTrue(verifying.verify(wireSignature), "signature from the loaded sk key should verify");
    }

    private static byte[] rawEd25519PublicKey(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    private static String buildOpenSshV1SkEd25519(byte[] rawPublicKey, String application, byte flags, byte[] keyHandle, String comment) {
        byte[] publicKeyBlob = new Buffer.PlainBuffer()
                .putString(KeyType.SK_ED25519.toString())
                .putBytes(rawPublicKey)
                .putString(application)
                .getCompactData();

        Buffer.PlainBuffer privateSection = new Buffer.PlainBuffer()
                .putUInt32(0x01020304L) // checkint1
                .putUInt32(0x01020304L) // checkint2
                .putString(KeyType.SK_ED25519.toString())
                .putBytes(rawPublicKey)
                .putString(application)
                .putByte(flags)
                .putBytes(keyHandle)
                .putString("") // reserved
                .putString(comment);
        // pad to the "none" cipher block size of 8 with 1, 2, 3, ...
        byte pad = 1;
        while (privateSection.available() % 8 != 0) {
            privateSection.putByte(pad++);
        }

        byte[] blob = new Buffer.PlainBuffer()
                .putRawBytes("openssh-key-v1\0".getBytes(StandardCharsets.UTF_8))
                .putString("none") // cipher
                .putString("none") // kdf
                .putString("")     // kdf options
                .putUInt32(1L)     // number of keys
                .putString(publicKeyBlob)
                .putString(privateSection.getCompactData())
                .getCompactData();

        return "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + Base64.getEncoder().encodeToString(blob) + "\n"
                + "-----END OPENSSH PRIVATE KEY-----\n";
    }

    private static SecurityKeySigner softwareAuthenticator(PrivateKey credentialKey) {
        return request -> {
            byte[] rpIdHash = sha256(request.getApplication().getBytes(StandardCharsets.UTF_8));
            byte[] authenticatorData = new byte[rpIdHash.length + 5];
            System.arraycopy(rpIdHash, 0, authenticatorData, 0, rpIdHash.length);
            authenticatorData[rpIdHash.length] = request.getMinFlags();
            // counter = 1
            authenticatorData[authenticatorData.length - 1] = 1;
            byte[] signed = new byte[authenticatorData.length + request.getChallenge().length];
            System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
            System.arraycopy(request.getChallenge(), 0, signed, authenticatorData.length, request.getChallenge().length);
            try {
                java.security.Signature s = java.security.Signature.getInstance("Ed25519");
                s.initSign(credentialKey);
                s.update(signed);
                return new SecurityKeySignatureData(request.getMinFlags(), 1L, s.sign());
            } catch (Exception e) {
                throw new java.io.IOException(e);
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
