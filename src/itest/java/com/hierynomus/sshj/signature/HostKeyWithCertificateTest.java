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
package com.hierynomus.sshj.signature;

import java.io.File;
import java.io.StringReader;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.hierynomus.sshj.SshdContainer;
import com.hierynomus.sshj.SshdContainer.SshdConfigBuilder;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;

import static com.hierynomus.sshj.SshdContainer.withSshdContainer;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HostKeyWithCertificateTest {

    @ParameterizedTest(name = "Should connect to server that has a signed host public key {0}")
    @ValueSource(strings = { "ssh_host_ecdsa_256_key", "ssh_host_ecdsa_384_key", "ssh_host_ecdsa_521_key",
            "ssh_host_ed25519_384_key" })
    // TODO "ssh_host_rsa_2048_key" fails with "HOST_KEY_NOT_VERIFIABLE" after upgrade to new OpenSSH version
    public void shouldConnectToServerWithSignedHostKey(String hostkey) throws Throwable {
        File caPubKey = new File("src/itest/resources/keyfiles/certificates/CA_rsa.pem.pub");
        String caPubKeyContents = Files.readString(caPubKey.toPath());
        String address = "127.0.0.1";

        SshdConfigBuilder b = SshdConfigBuilder.defaultBuilder().with("PasswordAuthentication", "yes");

        withSshdContainer(SshdContainer.Builder.defaultBuilder().withSshdConfig(b).addHostKey("test-container/host_keys/" + hostkey).addHostKeyCertificate("test-container/host_keys/" + hostkey + "-cert.pub"), sshd -> {
            String knownHosts = List.of("@cert-authority " + address + " " + caPubKeyContents,
                    "@cert-authority [" + address + "]:" + sshd.getFirstMappedPort() + " " + caPubKeyContents).stream()
                    .reduce("", (a, b1) -> a + "\n" + b1);
            DefaultConfig cfg = new DefaultConfig();
            try (SSHClient c = new SSHClient(cfg)) {
                c.addHostKeyVerifier(new OpenSSHKnownHosts(new StringReader(knownHosts)));
                c.connect(address, sshd.getFirstMappedPort());

                c.authPassword("sshj", "ultrapassword");

                assertTrue(c.isAuthenticated());
            }
        });

    }
}
