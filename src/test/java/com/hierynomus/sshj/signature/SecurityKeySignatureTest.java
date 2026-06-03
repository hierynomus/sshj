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
import com.hierynomus.sshj.userauth.fido.SecurityKeySigningRequest;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.signature.Signature;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validates FIDO/U2F (sk-*) signature handling without any hardware, by synthesising an
 * authenticator in software: the test holds the credential private key, builds the signed blob
 * (SHA256(application) || flags || counter || SHA256(message)) by hand per PROTOCOL.u2f, and checks
 * both verification and the signing path against it.
 */
public class SecurityKeySignatureTest {

    private static final String APPLICATION = "ssh:";
    private static final byte FLAGS = 0x05; // user-present + user-verified
    private static final long COUNTER = 0x01020304L;

    @Test
    public void skEcdsaVerifies() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = "the ssh data to be signed".getBytes(StandardCharsets.UTF_8);

        byte[] wireSig = synthesizeEcdsaSignature(kp.getPrivate(), message, FLAGS, COUNTER);

        Signature sig = new SignatureSkEcdsa();
        sig.initVerify(new SecurityKeyPublicKey(kp.getPublic(), APPLICATION));
        sig.update(message);
        assertTrue(sig.verify(wireSig), "sk-ecdsa signature should verify");
    }

    @Test
    public void skEd25519Verifies() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] message = "the ssh data to be signed".getBytes(StandardCharsets.UTF_8);

        byte[] wireSig = synthesizeEd25519Signature(kp.getPrivate(), message, FLAGS, COUNTER);

        Signature sig = new SignatureSkEd25519();
        sig.initVerify(new SecurityKeyPublicKey(kp.getPublic(), APPLICATION));
        sig.update(message);
        assertTrue(sig.verify(wireSig), "sk-ssh-ed25519 signature should verify");
    }

    @Test
    public void tamperedMessageFailsVerification() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] message = "original".getBytes(StandardCharsets.UTF_8);
        byte[] wireSig = synthesizeEd25519Signature(kp.getPrivate(), message, FLAGS, COUNTER);

        Signature sig = new SignatureSkEd25519();
        sig.initVerify(new SecurityKeyPublicKey(kp.getPublic(), APPLICATION));
        sig.update("tampered".getBytes(StandardCharsets.UTF_8));
        assertFalse(sig.verify(wireSig), "verification must fail when the signed message differs");
    }

    @Test
    public void tamperedCounterFailsVerification() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] message = "msg".getBytes(StandardCharsets.UTF_8);
        // The signature was made over COUNTER, but the wire claims COUNTER+1 -> must fail.
        byte[] inner = ed25519Inner(kp.getPrivate(), message, FLAGS, COUNTER);
        byte[] wireSig = new Buffer.PlainBuffer()
                .putString(KeyType.SK_ED25519.toString())
                .putBytes(inner)
                .putByte(FLAGS)
                .putUInt32(COUNTER + 1)
                .getCompactData();

        Signature sig = new SignatureSkEd25519();
        sig.initVerify(new SecurityKeyPublicKey(kp.getPublic(), APPLICATION));
        sig.update(message);
        assertFalse(sig.verify(wireSig), "verification must fail when the counter is altered");
    }

    /** Drives the full signing path (SecurityKeySigner -> Signature#sign/#encode) and verifies the result. */
    @Test
    public void skEcdsaSignThenVerifyRoundTrips() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = "round trip".getBytes(StandardCharsets.UTF_8);

        SecurityKeyPublicKey pub = new SecurityKeyPublicKey(kp.getPublic(), APPLICATION);
        SecurityKeySigner signer = softwareAuthenticator(kp.getPrivate(), "SHA256withECDSA", FLAGS, COUNTER);
        SecurityKeyPrivateKey priv = new SecurityKeyPrivateKey(KeyType.SK_ECDSA.toString(), pub, FLAGS, new byte[]{1, 2, 3}, signer);

        Signature signing = new SignatureSkEcdsa();
        signing.initSign(priv);
        signing.update(message);
        byte[] wireSig = signing.encode(signing.sign());

        Signature verifying = new SignatureSkEcdsa();
        verifying.initVerify(pub);
        verifying.update(message);
        assertTrue(verifying.verify(wireSig), "signed sk-ecdsa value should verify");
    }

    @Test
    public void skEd25519SignThenVerifyRoundTrips() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] message = "round trip".getBytes(StandardCharsets.UTF_8);

        SecurityKeyPublicKey pub = new SecurityKeyPublicKey(kp.getPublic(), APPLICATION);
        SecurityKeySigner signer = softwareAuthenticator(kp.getPrivate(), "Ed25519", FLAGS, COUNTER);
        SecurityKeyPrivateKey priv = new SecurityKeyPrivateKey(KeyType.SK_ED25519.toString(), pub, FLAGS, new byte[]{9}, signer);

        Signature signing = new SignatureSkEd25519();
        signing.initSign(priv);
        signing.update(message);
        byte[] wireSig = signing.encode(signing.sign());

        Signature verifying = new SignatureSkEd25519();
        verifying.initVerify(pub);
        verifying.update(message);
        assertTrue(verifying.verify(wireSig), "signed sk-ssh-ed25519 value should verify");

        // The encoded wire signature must carry the flags and counter the authenticator reported.
        Buffer.PlainBuffer buf = new Buffer.PlainBuffer(wireSig);
        assertArrayEquals(KeyType.SK_ED25519.toString().getBytes(StandardCharsets.UTF_8), buf.readBytes());
        buf.readBytes(); // raw signature
        org.junit.jupiter.api.Assertions.assertEquals(FLAGS, buf.readByte());
        org.junit.jupiter.api.Assertions.assertEquals(COUNTER, buf.readUInt32());
    }

    // --- software authenticator helpers (these stand in for the YubiKey) ---

    /**
     * A {@link SecurityKeySigner} that signs in software, exactly as a real authenticator would:
     * it rebuilds the authenticator data and signs authenticatorData || clientDataHash.
     */
    private static SecurityKeySigner softwareAuthenticator(PrivateKey credentialKey, String jcaAlgorithm, byte flags, long counter) {
        return request -> {
            byte[] signedData = concat(authenticatorData(request.getApplication(), flags, counter), request.getChallenge());
            byte[] deviceSig = jcaSign(credentialKey, jcaAlgorithm, signedData);
            return new SecurityKeySignatureData(flags, counter, deviceSig);
        };
    }

    private static byte[] synthesizeEcdsaSignature(PrivateKey credentialKey, byte[] message, byte flags, long counter) throws Exception {
        byte[] signedData = concat(authenticatorData(APPLICATION, flags, counter), sha256(message));
        byte[] der = jcaSign(credentialKey, "SHA256withECDSA", signedData);
        byte[] inner = derToSshEcdsa(der);
        return new Buffer.PlainBuffer()
                .putString(KeyType.SK_ECDSA.toString())
                .putBytes(inner)
                .putByte(flags)
                .putUInt32(counter)
                .getCompactData();
    }

    private static byte[] synthesizeEd25519Signature(PrivateKey credentialKey, byte[] message, byte flags, long counter) throws Exception {
        byte[] inner = ed25519Inner(credentialKey, message, flags, counter);
        return new Buffer.PlainBuffer()
                .putString(KeyType.SK_ED25519.toString())
                .putBytes(inner)
                .putByte(flags)
                .putUInt32(counter)
                .getCompactData();
    }

    private static byte[] ed25519Inner(PrivateKey credentialKey, byte[] message, byte flags, long counter) throws Exception {
        byte[] signedData = concat(authenticatorData(APPLICATION, flags, counter), sha256(message));
        return jcaSign(credentialKey, "Ed25519", signedData);
    }

    /** authenticatorData = SHA256(application) || flags || counter (4 bytes big-endian). Built by hand. */
    private static byte[] authenticatorData(String application, byte flags, long counter) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(sha256(application.getBytes(StandardCharsets.UTF_8)));
            out.write(flags);
            out.write((int) ((counter >>> 24) & 0xff));
            out.write((int) ((counter >>> 16) & 0xff));
            out.write((int) ((counter >>> 8) & 0xff));
            out.write((int) (counter & 0xff));
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] derToSshEcdsa(byte[] der) throws Exception {
        com.hierynomus.asn1.ASN1InputStream in = new com.hierynomus.asn1.ASN1InputStream(
                new com.hierynomus.asn1.encodingrules.der.DERDecoder(), new java.io.ByteArrayInputStream(der));
        com.hierynomus.asn1.types.constructed.ASN1Sequence seq = in.readObject();
        java.math.BigInteger r = ((com.hierynomus.asn1.types.primitive.ASN1Integer) seq.get(0)).getValue();
        java.math.BigInteger s = ((com.hierynomus.asn1.types.primitive.ASN1Integer) seq.get(1)).getValue();
        return new Buffer.PlainBuffer().putMPInt(r).putMPInt(s).getCompactData();
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
