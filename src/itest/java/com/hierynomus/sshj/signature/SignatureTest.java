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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.SshdContainer;
import com.hierynomus.sshj.SshdContainer.SshdConfigBuilder;
import com.hierynomus.sshj.key.KeyAlgorithms;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;

@Testcontainers
public class SignatureTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer(SshdContainer.Builder.defaultBuilder().withSshdConfig(SshdConfigBuilder.defaultBuilder().with("HostKeyAlgorithms", "+ssh-rsa").with("PubkeyAcceptedAlgorithms", "+ssh-rsa")).withAllKeys());

    public static Stream<KeyAlgorithms.Factory> algs() {
        return Stream.of(KeyAlgorithms.SSHRSA(), KeyAlgorithms.RSASHA256(), KeyAlgorithms.RSASHA512());
    }

    @ParameterizedTest(name = "should correctly connect with Signature {0}")
    @MethodSource("algs")
    public void shouldCorrectlyConnectWithMac(KeyAlgorithms.Factory alg) throws Throwable {
        Config c = new DefaultConfig();
        c.setKeyAlgorithms(List.of(alg));
        try (SSHClient client = sshd.getConnectedClient(c)) {
            client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa");

            assertTrue(client.isAuthenticated());
        }
    }

}
