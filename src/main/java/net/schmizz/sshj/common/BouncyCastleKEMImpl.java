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

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * {@link SshjKEM} backed by Bouncy Castle's lightweight ML-KEM API.
 *
 * <p>This is the only class that refers to Bouncy Castle ML-KEM types. It must only be loaded through
 * {@link BouncyCastleKEM}, after {@link #probe()} has succeeded, so that a missing or incompatible Bouncy
 * Castle surfaces as a {@link LinkageError} there rather than at an arbitrary call site.</p>
 *
 * <p>Written against the Bouncy Castle 1.87 package layout (ML-KEM in {@code org.bouncycastle.crypto.kems}
 * and {@code org.bouncycastle.crypto.params}). An older Bouncy Castle that lacks those classes makes the
 * fallback unavailable rather than failing at runtime.</p>
 */
final class BouncyCastleKEMImpl implements SshjKEM {

    /**
     * Shared {@link SecureRandom}. {@code SecureRandom} is thread-safe and lazily seeded by the JDK, so a
     * single instance avoids paying the (potentially blocking) seed cost on every encapsulation.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Touches every Bouncy Castle class this implementation needs, so that an absent or incompatible
     * Bouncy Castle fails here with a {@link LinkageError} (for example {@link NoClassDefFoundError}).
     */
    static void probe() {
        new MLKEMGenerator(SECURE_RANDOM);
        // Class literals resolve (and so load and link) the class, failing here if it is missing.
        Objects.requireNonNull(MLKEMExtractor.class);
        Objects.requireNonNull(MLKEMPrivateKeyParameters.class);
        Objects.requireNonNull(SecretWithEncapsulation.class);
        Objects.requireNonNull(PublicKeyFactory.class);
        Objects.requireNonNull(PrivateKeyFactory.class);
    }

    @Override
    public Encapsulated encapsulate(PublicKey peerPublicKey) throws GeneralSecurityException {
        final AsymmetricKeyParameter parameters;
        try {
            parameters = PublicKeyFactory.createKey(peerPublicKey.getEncoded());
        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to read ML-KEM public key", e);
        }
        final SecretWithEncapsulation result = new MLKEMGenerator(SECURE_RANDOM).generateEncapsulated(parameters);
        try {
            return new Encapsulated(result.getEncapsulation(), result.getSecret());
        } finally {
            try {
                result.destroy();
            } catch (Exception ignore) {
                // best-effort wipe
            }
        }
    }

    @Override
    public byte[] decapsulate(PrivateKey ourPrivateKey, byte[] ciphertext) throws GeneralSecurityException {
        final AsymmetricKeyParameter parameters;
        try {
            parameters = PrivateKeyFactory.createKey(ourPrivateKey.getEncoded());
        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to read ML-KEM private key", e);
        }
        if (!(parameters instanceof MLKEMPrivateKeyParameters)) {
            throw new GeneralSecurityException(
                    "Expected ML-KEM private key but got " + parameters.getClass().getName());
        }
        return new MLKEMExtractor((MLKEMPrivateKeyParameters) parameters).extractSecret(ciphertext);
    }
}
