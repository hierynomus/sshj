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

import java.security.PublicKey;
import java.util.Objects;

/**
 * A public key for an OpenSSH FIDO/U2F security key, i.e. one of the
 * {@code sk-ecdsa-sha2-nistp256@openssh.com} or {@code sk-ssh-ed25519@openssh.com} key types.
 * <p>
 * Such a key is a regular ECDSA (NIST P-256) or Ed25519 public key with an additional
 * {@code application} string attached (typically {@code "ssh:"}). The application string is part of
 * the SSH wire encoding of the key and is mixed into every signature the authenticator produces, so
 * it has to travel with the key. This wrapper keeps the underlying {@link PublicKey} and the
 * application together.
 * <p>
 * It deliberately does <em>not</em> implement {@link java.security.interfaces.ECKey} or
 * {@code EdECKey} so that {@link net.schmizz.sshj.common.KeyType#fromKey(java.security.Key)} can tell
 * a security-key public key apart from a plain ECDSA/Ed25519 public key.
 *
 * @see <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f">PROTOCOL.u2f</a>
 */
public class SecurityKeyPublicKey implements PublicKey {
    private static final long serialVersionUID = 1L;

    private final PublicKey delegate;
    private final String application;

    public SecurityKeyPublicKey(PublicKey delegate, String application) {
        this.delegate = Objects.requireNonNull(delegate, "delegate public key");
        this.application = Objects.requireNonNull(application, "application");
    }

    /** @return the underlying ECDSA (P-256) or Ed25519 public key. */
    public PublicKey getDelegate() {
        return delegate;
    }

    /** @return the application string, e.g. {@code "ssh:"}. */
    public String getApplication() {
        return application;
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return delegate.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        // The application string is only part of the SSH wire encoding (see KeyType), not of the
        // JCA X.509 encoding. Callers that need the SSH blob must go through KeyType#putPubKeyIntoBuffer.
        return delegate.getEncoded();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SecurityKeyPublicKey)) {
            return false;
        }
        SecurityKeyPublicKey that = (SecurityKeyPublicKey) o;
        return delegate.equals(that.delegate) && application.equals(that.application);
    }

    @Override
    public int hashCode() {
        return Objects.hash(delegate, application);
    }

    @Override
    public String toString() {
        return "SecurityKeyPublicKey{application=" + application + ", delegate=" + delegate + "}";
    }
}
