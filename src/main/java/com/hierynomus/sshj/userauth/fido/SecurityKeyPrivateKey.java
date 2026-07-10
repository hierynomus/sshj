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

import java.security.PrivateKey;

/**
 * The "private" half of an OpenSSH FIDO/U2F security key.
 * <p>
 * Unlike a normal private key this holds no secret scalar: the secret never leaves the hardware
 * authenticator. What an {@code sk-*} private key file actually stores - and what this class carries
 * - is the {@link #getApplication() application}, the {@link #getKeyHandle() key handle} (credential
 * id) and the authenticator {@link #getFlags() flags}. Signing is delegated to a
 * {@link SecurityKeySigner}, which drives the hardware.
 *
 * @see SecurityKeySigner
 */
public class SecurityKeyPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1L;

    private final String keyTypeName;
    private final SecurityKeyPublicKey publicKey;
    private final byte flags;
    private final byte[] keyHandle;
    private final transient SecurityKeySigner signer;

    public SecurityKeyPrivateKey(String keyTypeName, SecurityKeyPublicKey publicKey, byte flags, byte[] keyHandle, SecurityKeySigner signer) {
        this.keyTypeName = keyTypeName;
        this.publicKey = publicKey;
        this.flags = flags;
        this.keyHandle = keyHandle;
        this.signer = signer;
    }

    /** @return the SSH key type, e.g. {@code sk-ssh-ed25519@openssh.com}. */
    public String getKeyTypeName() {
        return keyTypeName;
    }

    public SecurityKeyPublicKey getPublicKey() {
        return publicKey;
    }

    public String getApplication() {
        return publicKey.getApplication();
    }

    /** @return the authenticator flags the key was created with (user-presence / user-verification). */
    public byte getFlags() {
        return flags;
    }

    public byte[] getKeyHandle() {
        return keyHandle;
    }

    /** @return the bridge to the hardware authenticator, or {@code null} if none was attached. */
    public SecurityKeySigner getSigner() {
        return signer;
    }

    @Override
    public String getAlgorithm() {
        return publicKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
        // No standard encoding: the key material is opaque and lives in the authenticator.
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
