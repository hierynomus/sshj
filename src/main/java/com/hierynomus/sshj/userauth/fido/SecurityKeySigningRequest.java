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

import net.schmizz.sshj.common.SSHRuntimeException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The inputs a {@link SecurityKeySigner} needs to make an authenticator produce an assertion.
 * <p>
 * In WebAuthn terms: {@link #getApplication() application} is the RP id, {@link #getChallenge()
 * challenge} is the client-data hash, and {@link #getKeyHandle() keyHandle} identifies the
 * credential to assert with.
 * <p>
 * The request carries the SSH data to sign in two forms, because the two kinds of signer need
 * different ones:
 * <ul>
 *   <li>{@link #getData()} is the data itself. Use it when the authenticator is reached through an
 *       OpenSSH security key middleware ({@code sk_sign()} in {@code libsk-libfido2},
 *       {@code ssh-keychain.dylib}, ...), which takes the message and derives the client-data hash
 *       itself.</li>
 *   <li>{@link #getChallenge()} is the SHA-256 of that data, i.e. the client-data hash. Use it when
 *       talking to the authenticator at the CTAP / WebAuthn level, which takes the hash.</li>
 * </ul>
 * Passing {@link #getChallenge()} to a middleware makes it hash a second time, so the authenticator
 * signs {@code SHA256(SHA256(data))} and the server rejects the signature.
 */
public class SecurityKeySigningRequest {

    private final String keyTypeName;
    private final String application;
    private final byte[] keyHandle;
    private final byte[] data;
    private final byte[] challenge;
    private final byte minFlags;

    /**
     * Creates a request that knows only the challenge, not the data it was derived from.
     * {@link #getData()} returns {@code null} for such a request, so it cannot be used with a
     * middleware signer.
     *
     * @param keyTypeName the SSH key type, e.g. {@code sk-ssh-ed25519@openssh.com}
     * @param application the application string, e.g. {@code "ssh:"}
     * @param keyHandle   the credential / key handle stored in the private key file
     * @param challenge   the SHA-256 of the SSH data to sign
     * @param minFlags    the minimum authenticator flags requested by the key file
     * @deprecated use {@link #forData(String, String, byte[], byte[], byte)}, which takes the data and derives
     * the challenge, so that both are always available to the signer
     */
    @Deprecated
    public SecurityKeySigningRequest(String keyTypeName, String application, byte[] keyHandle, byte[] challenge, byte minFlags) {
        this(keyTypeName, application, keyHandle, null, challenge, minFlags);
    }

    /**
     * Creates a request for the given SSH data; the challenge (client-data hash) is derived from it.
     *
     * @param keyTypeName the SSH key type, e.g. {@code sk-ssh-ed25519@openssh.com}
     * @param application the application string, e.g. {@code "ssh:"}
     * @param keyHandle   the credential / key handle stored in the private key file
     * @param data        the SSH data to sign
     * @param minFlags    the minimum authenticator flags requested by the key file
     * @return the request, which provides both {@link #getData()} and {@link #getChallenge()}
     */
    public static SecurityKeySigningRequest forData(String keyTypeName, String application, byte[] keyHandle, byte[] data,
                                                    byte minFlags) {
        return new SecurityKeySigningRequest(keyTypeName, application, keyHandle, data.clone(), sha256(data), minFlags);
    }

    private SecurityKeySigningRequest(String keyTypeName, String application, byte[] keyHandle, byte[] data, byte[] challenge,
                                      byte minFlags) {
        this.keyTypeName = keyTypeName;
        this.application = application;
        this.keyHandle = keyHandle;
        this.data = data;
        this.challenge = challenge;
        this.minFlags = minFlags;
    }

    /** @return the SSH key type, e.g. {@code sk-ssh-ed25519@openssh.com}. */
    public String getKeyTypeName() {
        return keyTypeName;
    }

    /** @return the application string, e.g. {@code "ssh:"} (the WebAuthn RP id). */
    public String getApplication() {
        return application;
    }

    /** @return the credential / key handle stored in the private key file. */
    public byte[] getKeyHandle() {
        return keyHandle;
    }

    /**
     * @return the SSH data to sign. Pass this to an OpenSSH security key middleware's {@code sk_sign()}, which
     * derives the client-data hash from it itself. {@code null} only for a request created with the
     * deprecated challenge-only constructor.
     */
    public byte[] getData() {
        return data == null ? null : data.clone();
    }

    /**
     * @return the SHA-256 of the SSH data to sign (the WebAuthn client-data hash). Pass this to an
     * authenticator that is driven at the CTAP / WebAuthn level. Do <em>not</em> pass it to an OpenSSH
     * security key middleware, which hashes its input again; use {@link #getData()} for that.
     */
    public byte[] getChallenge() {
        return challenge;
    }

    /**
     * @return the minimum authenticator flags requested by the key file: bit 0
     * ({@code SSH_SK_USER_PRESENCE_REQD}) and bit 2 ({@code SSH_SK_USER_VERIFICATION_REQD}). An
     * implementation should ask the authenticator for at least these.
     */
    public byte getMinFlags() {
        return minFlags;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new SSHRuntimeException(e);
        }
    }
}
