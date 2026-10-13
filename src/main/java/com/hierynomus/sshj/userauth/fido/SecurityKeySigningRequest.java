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

/**
 * The inputs a {@link SecurityKeySigner} needs to make an authenticator produce an assertion.
 * <p>
 * In WebAuthn terms: {@link #getApplication() application} is the RP id, {@link #getChallenge()
 * challenge} is the client-data hash, and {@link #getKeyHandle() keyHandle} identifies the
 * credential to assert with.
 */
public class SecurityKeySigningRequest {

    private final String keyTypeName;
    private final String application;
    private final byte[] keyHandle;
    private final byte[] challenge;
    private final byte minFlags;

    public SecurityKeySigningRequest(String keyTypeName, String application, byte[] keyHandle, byte[] challenge, byte minFlags) {
        this.keyTypeName = keyTypeName;
        this.application = application;
        this.keyHandle = keyHandle;
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

    /** @return the SHA-256 of the SSH data to sign (the WebAuthn client-data hash). */
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
}
