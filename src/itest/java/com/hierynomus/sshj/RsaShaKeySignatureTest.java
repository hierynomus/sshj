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

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.hierynomus.sshj.SshdContainer.SshdConfigBuilder;
import com.hierynomus.sshj.key.KeyAlgorithms;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static com.hierynomus.sshj.SshdContainer.withSshdContainer;

public class RsaShaKeySignatureTest {

    public static Stream<Arguments> hostKeysAndAlgorithms() {
        return Stream.of(
                Arguments.of("ssh_host_ecdsa_256_key", KeyAlgorithms.ECDSASHANistp256()),
                Arguments.of("ssh_host_ecdsa_384_key", KeyAlgorithms.ECDSASHANistp384()),
                Arguments.of("ssh_host_ecdsa_521_key", KeyAlgorithms.ECDSASHANistp521()),
                Arguments.of("ssh_host_ed25519_384_key", KeyAlgorithms.EdDSA25519()),
                Arguments.of("ssh_host_rsa_2048_key", KeyAlgorithms.RSASHA512()));
    }

    @ParameterizedTest(name = "Should connect to server that does not support ssh-rsa with host key {1}")
    @MethodSource("hostKeysAndAlgorithms")
    public void shouldConnectToServerThatDoesNotSupportSshRsaWithHostKey(String key, KeyAlgorithms.Factory algorithm)
            throws Throwable {
        SshdConfigBuilder configBuilder = SshdConfigBuilder
                .defaultBuilder()
                .with("PubkeyAcceptedAlgorithms", "rsa-sha2-512,rsa-sha2-256,ssh-ed25519");
        withSshdContainer(SshdContainer.Builder.defaultBuilder()
                .withSshdConfig(configBuilder).addHostKey("test-container/host_keys/" + key), sshd -> {
                    Config c = new DefaultConfig();
                    c.setKeyAlgorithms(List.of(KeyAlgorithms.RSASHA512(), KeyAlgorithms.RSASHA256(), algorithm));

                    SSHClient client = sshd.getConnectedClient(c);
                    client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1");

                    assertTrue(client.isAuthenticated());

                    client.disconnect();
                });
    }

    @ParameterizedTest(name = "Should connect to a default server with host key {1} with a default config")
    @MethodSource("hostKeysAndAlgorithms")
    public void shouldConnectToDefaultServer(String key, KeyAlgorithms.Factory algorithm) throws Throwable {
        withSshdContainer(SshdContainer.Builder.defaultBuilder().addHostKey("test-container/host_keys/" + key),
                sshd -> {
                    SSHClient client = sshd.getConnectedClient();
                    client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1");

                    assertTrue(client.isAuthenticated());

                    client.disconnect();
                });
    }

    @ParameterizedTest(name = "Should connect to a server that only supports ssh-rsa with host key {1}")
    @MethodSource("hostKeysAndAlgorithms")
    public void shouldConnectToSshRsaOnlyServer(String key, KeyAlgorithms.Factory algorithm) throws Throwable {
        SshdConfigBuilder configBuilder = SshdConfigBuilder
                .defaultBuilder()
                .with("PubkeyAcceptedAlgorithms", "ssh-rsa,ssh-ed25519");

        withSshdContainer(SshdContainer.Builder.defaultBuilder()
                .withSshdConfig(configBuilder).addHostKey("test-container/host_keys/" + key), sshd -> {
                    Config c = new DefaultConfig();
                    c.setKeyAlgorithms(List.of(KeyAlgorithms.SSHRSA(), algorithm));
                    SSHClient client = sshd.getConnectedClient(c);
                    client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1");

                    assertTrue(client.isAuthenticated());
                    client.disconnect();
                });
    }
}
