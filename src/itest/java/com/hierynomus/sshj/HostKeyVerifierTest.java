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
package com.hierynomus.sshj;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.key.KeyAlgorithms;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.TransportException;

@Testcontainers
public class HostKeyVerifierTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer();

    public static Stream<Arguments> signatureAlgos() {
        return Stream.of(
            Arguments.of(KeyAlgorithms.ECDSASHANistp256(), "d3:6a:a9:52:05:ab:b5:48:dd:73:60:18:0c:3a:f0:a3"),
            Arguments.of(KeyAlgorithms.EdDSA25519(), "dc:68:38:ce:fc:6f:2c:d6:6d:6b:34:eb:5c:f0:41:6a"));
    }

    @ParameterizedTest(name = "Should connect with signature verified for Key Algorithm {0}")
    @MethodSource("signatureAlgos")
    public void shouldConnectWithSignatureVerified(KeyAlgorithms.Factory alg, String fingerprint) throws Throwable {
        Config config = new DefaultConfig();
        config.setKeyAlgorithms(List.of(alg));

        try (SSHClient client = new SSHClient(config)) {
            client.addHostKeyVerifier(fingerprint);
            client.connect(sshd.getHost(), sshd.getFirstMappedPort());

            assertTrue(client.isConnected());
        }
    }

    @Test
    public void shouldDeclineWrongKey() throws Throwable {
        try (SSHClient client = new SSHClient()) {
            assertThrows(TransportException.class, () -> {
                client.addHostKeyVerifier("d4:6a:a9:52:05:ab:b5:48:dd:73:60:18:0c:3a:f0:a3");
                client.connect(sshd.getHost(), sshd.getFirstMappedPort());
            });
        }
    }
}
