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

package net.schmizz.sshj.keyprovider;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.util.CorruptBase64;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class CorruptedPublicKeyTest {
    private final Path keyRoot = Path.of("src/test/resources");

    @TempDir
    public Path tempDir;

    @ParameterizedTest
    @CsvSource({
            "keyformats/ecdsa_opensshv1,",
            "keyformats/openssh,",
            "keytypes/test_ecdsa_nistp521_2,",
            "keytypes/ed25519_protected, sshjtest",
    })
    public void corruptedPublicKey(String privateKeyFileName, String passphrase) throws IOException {
        Files.createDirectories(tempDir.resolve(privateKeyFileName).getParent());
        Files.copy(keyRoot.resolve(privateKeyFileName), tempDir.resolve(privateKeyFileName));

        {
            String publicKeyText;
            try (var reader = new BufferedReader(new FileReader(
                    keyRoot.resolve(privateKeyFileName + ".pub").toFile()))) {
                publicKeyText = reader.readLine();
            }

            String[] parts = publicKeyText.split("\\s+");
            parts[1] = CorruptBase64.corruptBase64(parts[1]);

            try (var writer = new FileWriter(tempDir.resolve(privateKeyFileName + ".pub").toFile())) {
                writer.write(String.join(" ", parts));
            }
        }

        // Must not throw an exception.
        try (var sshClient = new SSHClient()) {
            sshClient.loadKeys(
                    tempDir.resolve(privateKeyFileName).toString(),
                    Optional.ofNullable(passphrase).map(String::toCharArray).orElse(null)
            ).getPublic();
        }
    }
}
