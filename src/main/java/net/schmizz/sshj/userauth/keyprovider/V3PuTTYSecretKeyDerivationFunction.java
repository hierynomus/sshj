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
package net.schmizz.sshj.userauth.keyprovider;

import net.schmizz.sshj.common.ByteArrayUtils;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;
import java.util.Objects;

/**
 * PuTTY Key Derivation Function supporting Version 3 Key files with Argon2 Key Derivation using Bouncy Castle
 */
class V3PuTTYSecretKeyDerivationFunction implements PuTTYSecretKeyDerivationFunction {
    private static final String SECRET_KEY_ALGORITHM = "AES";

    private static final int KEY_LENGTH = 80;

    private final Map<String, String> headers;

    V3PuTTYSecretKeyDerivationFunction(final Map<String, String> headers) {
        this.headers = Objects.requireNonNull(headers, "Headers required");
    }

    /**
     * Derive Secret Key from provided passphrase characters
     *
     * @param passphrase Passphrase characters required
     * @return Derived Secret Key
     */
    public SecretKey deriveSecretKey(char[] passphrase) {
        Objects.requireNonNull(passphrase, "Passphrase required");

        final Argon2Parameters parameters = getParameters();
        final Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);

        final byte[] secretKeyEncoded = new byte[KEY_LENGTH];
        final int bytesGenerated = generator.generateBytes(passphrase, secretKeyEncoded);
        if (KEY_LENGTH == bytesGenerated) {
            return new SecretKeySpec(secretKeyEncoded, SECRET_KEY_ALGORITHM);
        } else {
            final String message = String.format("Argon2 bytes generated [%d] not expected", bytesGenerated);
            throw new IllegalStateException(message);
        }
    }

    private Argon2Parameters getParameters() {
        final int algorithmType = getAlgorithmType();

        final byte[] salt = ByteArrayUtils.parseHex(headers.get("Argon2-Salt"));
        final int iterations = Integer.parseInt(headers.get("Argon2-Passes"));
        final int memory = Integer.parseInt(headers.get("Argon2-Memory"));
        final int parallelism = Integer.parseInt(headers.get("Argon2-Parallelism"));

        return new Argon2Parameters.Builder(algorithmType)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memory)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();
    }

    private int getAlgorithmType() {
        final String algorithm = headers.get("Key-Derivation");

        final int algorithmType;
        if ("argon2i".equalsIgnoreCase(algorithm)) {
            algorithmType = Argon2Parameters.ARGON2_i;
        } else if ("argon2d".equalsIgnoreCase(algorithm)) {
            algorithmType = Argon2Parameters.ARGON2_d;
        } else if ("argon2id".equalsIgnoreCase(algorithm)) {
            algorithmType = Argon2Parameters.ARGON2_id;
        } else {
            final String message = String.format("Key-Derivation [%s] not supported", algorithm);
            throw new IllegalArgumentException(message);
        }

        return algorithmType;
    }
}
