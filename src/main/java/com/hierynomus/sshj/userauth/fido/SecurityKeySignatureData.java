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
 * The result of a {@link SecurityKeySigner} assertion: what the authenticator reported back.
 */
public class SecurityKeySignatureData {

    private final byte flags;
    private final long counter;
    private final byte[] signature;

    /**
     * @param flags     the authenticator data flags the device returned (user-presence, user-verified, ...)
     * @param counter   the signature counter the device returned (an unsigned 32-bit value)
     * @param signature the raw signature the device produced: an ASN.1 DER ECDSA signature for
     *                  {@code sk-ecdsa-sha2-nistp256@openssh.com}, or the raw 64-byte Ed25519
     *                  signature for {@code sk-ssh-ed25519@openssh.com}
     */
    public SecurityKeySignatureData(byte flags, long counter, byte[] signature) {
        this.flags = flags;
        this.counter = counter;
        this.signature = signature;
    }

    public byte getFlags() {
        return flags;
    }

    public long getCounter() {
        return counter;
    }

    public byte[] getSignature() {
        return signature;
    }
}
