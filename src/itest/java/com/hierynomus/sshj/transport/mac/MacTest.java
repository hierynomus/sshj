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
package com.hierynomus.sshj.transport.mac;

import static org.junit.Assert.assertTrue;

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

@Testcontainers
public class MacTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer();

    public static Stream<Macs.Factory> macs() {
        return Stream.of(Macs.HMACSHA2256(), Macs.HMACSHA2512(), Macs.HMACSHA2256Etm(), Macs.HMACSHA2512Etm());
    }

    @ParameterizedTest(name = "should correctly connect with MAC {0}")
    @MethodSource("macs")
    public void shouldCorrectlyConnectWithMac(Macs.Factory mac) throws Throwable {
        Config c = new DefaultConfig();
        c.setMACFactories(List.of(mac));
        try (SSHClient client = sshd.getConnectedClient(c)) {
            client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1");

            assertTrue(client.isAuthenticated());
        }
    }
}
