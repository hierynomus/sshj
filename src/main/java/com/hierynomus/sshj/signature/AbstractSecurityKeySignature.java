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
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.signature.AbstractSignatureDSA;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Base class for the OpenSSH FIDO/U2F security key signatures
 * ({@code sk-ecdsa-sha2-nistp256@openssh.com} and {@code sk-ssh-ed25519@openssh.com}).
 * <p>
 * The difference from an ordinary SSH signature is what actually gets signed. A FIDO authenticator
 * never sees the SSH payload directly; instead it signs a small fixed structure (WebAuthn calls it
 * the authenticator data plus the client-data hash):
 *
 * <pre>
 *   signed = SHA256(application) || flags || counter || SHA256(sshData)
 * </pre>
 *
 * and the wire signature carries the {@code flags} and {@code counter} so the verifier can rebuild
 * that structure:
 *
 * <pre>
 *   string  key type
 *   string  raw signature        (ECDSA r||s as two mpints, or 64-byte Ed25519 signature)
 *   byte    flags
 *   uint32  counter
 * </pre>
 *
 * Verification rebuilds {@code signed} and checks it with the underlying ECDSA/Ed25519 key. Signing
 * is delegated to a {@link SecurityKeySigner} (the hardware bridge); this class only hashes the SSH
 * payload, hands the challenge to the signer and assembles the wire format from what comes back.
 *
 * @see <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f">PROTOCOL.u2f</a>
 */
public abstract class AbstractSecurityKeySignature extends AbstractSignatureDSA {

    private final ByteArrayOutputStream sshData = new ByteArrayOutputStream();
    private String application;
    private SecurityKeyPrivateKey signingKey;
    private byte signedFlags;
    private long signedCounter;

    protected AbstractSecurityKeySignature(String algorithm, String keyTypeName) {
        super(algorithm, keyTypeName);
    }

    @Override
    public boolean isSignaturePreEncoded() {
        return true;
    }

    @Override
    public void initVerify(PublicKey publicKey) {
        if (!(publicKey instanceof SecurityKeyPublicKey)) {
            throw new SSHRuntimeException("Expected a SecurityKeyPublicKey but got: " + publicKey);
        }
        SecurityKeyPublicKey sk = (SecurityKeyPublicKey) publicKey;
        this.application = sk.getApplication();
        super.initVerify(sk.getDelegate());
    }

    @Override
    public void initSign(PrivateKey privateKey) {
        if (!(privateKey instanceof SecurityKeyPrivateKey)) {
            throw new SSHRuntimeException("Expected a SecurityKeyPrivateKey but got: " + privateKey);
        }
        this.signingKey = (SecurityKeyPrivateKey) privateKey;
        this.application = signingKey.getApplication();
    }

    @Override
    public void update(byte[] foo, int off, int len) {
        sshData.write(foo, off, len);
    }

    @Override
    public byte[] sign() {
        if (signingKey == null) {
            throw new SSHRuntimeException("initSign was not called with a SecurityKeyPrivateKey");
        }
        SecurityKeySigner signer = signingKey.getSigner();
        if (signer == null) {
            throw new SSHRuntimeException("No SecurityKeySigner attached to security key " + signingKey.getKeyTypeName()
                    + "; cannot reach the authenticator. Authenticate via ssh-agent or attach a SecurityKeySigner.");
        }
        byte[] challenge = sha256(sshData.toByteArray());
        SecurityKeySignatureData data;
        try {
            data = signer.sign(new SecurityKeySigningRequest(signingKey.getKeyTypeName(), application,
                    signingKey.getKeyHandle(), challenge, signingKey.getFlags()));
        } catch (IOException e) {
            throw new SSHRuntimeException("Security key signing failed", e);
        }
        this.signedFlags = data.getFlags();
        this.signedCounter = data.getCounter();
        return deviceSignatureToSsh(data.getSignature());
    }

    /**
     * Assemble the full SSH signature value: {@code string keyType || string rawSig || byte flags || uint32 counter}.
     * Relies on {@link #sign()} having been called first to capture the flags and counter.
     */
    @Override
    public byte[] encode(byte[] sshRawSignature) {
        return new Buffer.PlainBuffer()
                .putString(getSignatureName())
                .putBytes(sshRawSignature)
                .putByte(signedFlags)
                .putUInt32(signedCounter)
                .getCompactData();
    }

    @Override
    public boolean verify(byte[] sig) {
        Buffer.PlainBuffer buf = new Buffer.PlainBuffer(sig);
        try {
            String type = buf.readString();
            if (!getSignatureName().equals(type)) {
                throw new SSHRuntimeException("Expected '" + getSignatureName() + "' signature but got: " + type);
            }
            byte[] sshRawSignature = buf.readBytes();
            byte flags = buf.readByte();
            long counter = buf.readUInt32();

            byte[] signedData = buildSignedData(flags, counter, sha256(sshData.toByteArray()));
            signature.update(signedData);
            return signature.verify(sshSignatureToDevice(sshRawSignature));
        } catch (Buffer.BufferException | SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    /**
     * The exact bytes the authenticator signs: {@code SHA256(application) || flags || counter || clientDataHash}.
     */
    private byte[] buildSignedData(byte flags, long counter, byte[] clientDataHash) {
        byte[] rpIdHash = sha256(application.getBytes(StandardCharsets.UTF_8));
        return new Buffer.PlainBuffer()
                .putRawBytes(rpIdHash)
                .putByte(flags)
                .putUInt32(counter)
                .putRawBytes(clientDataHash)
                .getCompactData();
    }

    protected static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new SSHRuntimeException(e);
        }
    }

    /**
     * Convert the SSH raw-signature encoding read off the wire into the byte format the JCA
     * verification engine expects (DER for ECDSA, unchanged for Ed25519).
     */
    protected abstract byte[] sshSignatureToDevice(byte[] sshRawSignature) throws Buffer.BufferException;

    /**
     * Convert the authenticator's native signature into the SSH raw-signature encoding (r||s as two
     * mpints for ECDSA, unchanged for Ed25519).
     */
    protected abstract byte[] deviceSignatureToSsh(byte[] deviceSignature);
}
