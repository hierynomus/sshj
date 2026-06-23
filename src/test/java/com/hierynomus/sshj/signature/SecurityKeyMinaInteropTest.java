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
import com.hierynomus.sshj.userauth.fido.SecurityKeySignatureData;
import com.hierynomus.sshj.userauth.fido.SecurityKeySigner;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Interoperability check: a FIDO/U2F sk-ecdsa signature produced by sshj is verified by Apache MINA
 * sshd's independent implementation, and MINA also parses sshj's public-key blob. This pins the
 * public-key encoding and the signature format to a second implementation, not just sshj's own.
 * <p>
 * sk-ed25519 is intentionally not cross-checked against MINA here: MINA's sk-ed25519 verifier pulls
 * in net.i2p.crypto.eddsa, which sshj dropped in 0.39.0. That path is covered by
 * {@code SecurityKeySignatureTest} (spec-faithful construction and sign/verify round trips).
 */
public class SecurityKeyMinaInteropTest {

    private static final String APPLICATION = "ssh:";
    private static final byte FLAGS = 0x01; // user-present
    private static final long COUNTER = 42L;

    @Test
    public void minaVerifiesOurSkEcdsaSignature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = "interop ecdsa".getBytes(StandardCharsets.UTF_8);

        SecurityKeyPublicKey ourPublicKey = new SecurityKeyPublicKey(kp.getPublic(), APPLICATION);
        byte[] ourSignature = sign(new SignatureSkEcdsa(), KeyType.SK_ECDSA, ourPublicKey, kp.getPrivate(), "SHA256withECDSA", message);
        byte[] ourPublicKeyBlob = new Buffer.PlainBuffer().putPublicKey(ourPublicKey).getCompactData();

        java.security.PublicKey minaKey = new ByteArrayBuffer(ourPublicKeyBlob).getRawPublicKey();
        org.apache.sshd.common.signature.Signature minaVerifier = new org.apache.sshd.common.signature.SignatureSkECDSA();
        minaVerifier.initVerifier(null, minaKey);
        minaVerifier.update(null, message);
        assertTrue(minaVerifier.verify(null, ourSignature), "MINA should verify sshj's sk-ecdsa signature");
    }

    /** Produce an sk signature through sshj's signing path, with a software authenticator standing in for hardware. */
    private static byte[] sign(Signature signature, KeyType keyType, SecurityKeyPublicKey publicKey,
                               PrivateKey credentialKey, String jcaAlgorithm, byte[] message) {
        SecurityKeySigner signer = request -> {
            byte[] authenticatorData = authenticatorData(request.getApplication(), FLAGS, COUNTER);
            byte[] signed = concat(authenticatorData, request.getChallenge());
            byte[] deviceSig = jcaSign(credentialKey, jcaAlgorithm, signed);
            return new SecurityKeySignatureData(FLAGS, COUNTER, deviceSig);
        };
        SecurityKeyPrivateKey privateKey = new SecurityKeyPrivateKey(keyType.toString(), publicKey, FLAGS, new byte[]{7, 7}, signer);
        signature.initSign(privateKey);
        signature.update(message);
        return signature.encode(signature.sign());
    }

    private static byte[] authenticatorData(String application, byte flags, long counter) {
        byte[] rpIdHash = sha256(application.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[rpIdHash.length + 5];
        System.arraycopy(rpIdHash, 0, out, 0, rpIdHash.length);
        out[rpIdHash.length] = flags;
        out[rpIdHash.length + 1] = (byte) ((counter >>> 24) & 0xff);
        out[rpIdHash.length + 2] = (byte) ((counter >>> 16) & 0xff);
        out[rpIdHash.length + 3] = (byte) ((counter >>> 8) & 0xff);
        out[rpIdHash.length + 4] = (byte) (counter & 0xff);
        return out;
    }

    private static byte[] jcaSign(PrivateKey key, String algorithm, byte[] data) {
        try {
            java.security.Signature s = java.security.Signature.getInstance(algorithm);
            s.initSign(key);
            s.update(data);
            return s.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
