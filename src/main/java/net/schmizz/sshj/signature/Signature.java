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
package net.schmizz.sshj.signature;

import java.security.PrivateKey;
import java.security.PublicKey;

/** Signature interface for SSH used to sign or verify data. Usually wraps a {@code javax.crypto.Signature} object. */
public interface Signature {

    /**
     * Initialize this signature with the given public key for signature verification.
     *
     * Note that subsequent calls to either {@link #initVerify(PublicKey)} or {@link #initSign(PrivateKey)} will
     * overwrite prior initialization.
     *
     * @param pubkey the public key to use for signature verification
     */
    void initVerify(PublicKey pubkey);

    /**
     * Initialize this signature with the given private key for signing.
     *
     * Note that subsequent calls to either {@link #initVerify(PublicKey)} or {@link #initSign(PrivateKey)} will
     * overwrite prior initialization.
     *
     * @param prvkey the private key to use for signing
     */
    void initSign(PrivateKey prvkey);

    /**
     * Convenience method, same as calling {@link #update(byte[], int, int)} with offset as {@code 0} and {@code
     * H.length}.
     *
     * @param H the byte-array to update with
     */
    void update(byte[] H);

    /**
     * Update the computed signature with the given data.
     *
     * @param H   byte-array to update with
     * @param off offset within the array
     * @param len length until which to compute
     */
    void update(byte[] H, int off, int len);

    /**
     * Compute the signature.
     *
     * @return the computed signature
     */
    byte[] sign();

    /**
     * Encode the signature as blog
     * @param signature the signature to encode
     * @return Encoded signature
     */
    byte[] encode(byte[] signature);

    /**
     * Verify against the given signature.
     *
     * @param sig the signature to verify against
     *
     * @return {@code true} on successful verification, {@code false} on failure
     */
    boolean verify(byte[] sig);

}
