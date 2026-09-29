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
package net.schmizz.sshj.common;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * sshj-internal abstraction over the JDK 21+ {@code javax.crypto.KEM} API.
 *
 * <p>Obtained via {@link SecurityUtils#getKEM(String)}. Hides the reflective lookup
 * needed to compile against Java 8 source level while still using the modern KEM
 * API at runtime, and translates the four nested {@code KEM} classes into two
 * straightforward methods.</p>
 */
public interface SshjKEM {

    /**
     * Server-side encapsulation against a peer's public key.
     *
     * @param peerPublicKey peer public key
     * @return the produced ciphertext and the raw shared secret bytes
     * @throws GeneralSecurityException if encapsulation fails
     */
    Encapsulated encapsulate(PublicKey peerPublicKey) throws GeneralSecurityException;

    /**
     * Client-side decapsulation of a ciphertext using the local private key.
     *
     * @param ourPrivateKey local private key
     * @param ciphertext peer ciphertext
     * @return the raw shared secret bytes
     * @throws GeneralSecurityException if decapsulation fails
     */
    byte[] decapsulate(PrivateKey ourPrivateKey, byte[] ciphertext) throws GeneralSecurityException;

    /**
     * Result of {@link SshjKEM#encapsulate(PublicKey)}: the ciphertext to send to the peer
     * and the shared secret bytes for both sides to derive keys from.
     */
    final class Encapsulated {
        private final byte[] ciphertext;
        private final byte[] sharedSecret;

        public Encapsulated(byte[] ciphertext, byte[] sharedSecret) {
            this.ciphertext = ciphertext;
            this.sharedSecret = sharedSecret;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public byte[] getSharedSecret() {
            return sharedSecret;
        }
    }
}
