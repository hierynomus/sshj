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
package com.hierynomus.sshj.transport.kex;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.SshdContainer;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.transport.kex.Curve25519SHA256;
import net.schmizz.sshj.transport.kex.DHGexSHA1;
import net.schmizz.sshj.transport.kex.DHGexSHA256;
import net.schmizz.sshj.transport.kex.ECDHNistP;
import net.schmizz.sshj.transport.kex.KeyExchange;

@Testcontainers
public class KexTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer();

    public static Stream<Factory.Named<KeyExchange>> kex() {
        return Stream.of(
                DHGroups.Group1SHA1(),
                DHGroups.Group14SHA1(),
                DHGroups.Group14SHA256(),
                DHGroups.Group16SHA512(),
                DHGroups.Group18SHA512(),
                new DHGexSHA1.Factory(),
                new DHGexSHA256.Factory(),
                new Curve25519SHA256.Factory(),
                new Curve25519SHA256.FactoryLibSsh(),
                new ECDHNistP.Factory256(),
                new ECDHNistP.Factory384(),
                new ECDHNistP.Factory521());
    }

    @ParameterizedTest(name = "should correctly connect with Key Exchange {0}")
    @MethodSource("kex")
    public void shouldCorrectlyConnectWithMac(Factory.Named<KeyExchange> kex) throws Throwable {
        Config c = new DefaultConfig();
        c.setKeyExchangeFactories(List.of(kex));
        try (SSHClient client = sshd.getConnectedClient(c)) {
            client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1");

            assertTrue(client.isAuthenticated());
        }
    }
}
