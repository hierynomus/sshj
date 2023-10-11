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

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.transport.kex.DHGexSHA1;
import net.schmizz.sshj.transport.kex.DHGexSHA256;
import net.schmizz.sshj.transport.kex.ECDHNistP;
import net.schmizz.sshj.transport.random.JCERandom;
import net.schmizz.sshj.transport.random.SingletonRandomFactory;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.server.kex.DHGEXServer;
import org.apache.sshd.server.kex.DHGServer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;

public class KeyExchangeTest {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public static Collection<Object[]> getParameters() {
        return Arrays.asList(new Object[][] {
                { DHGEXServer.newFactory(BuiltinDHFactories.dhgex), new DHGexSHA1.Factory() },
                { DHGEXServer.newFactory(BuiltinDHFactories.dhgex256), new DHGexSHA256.Factory() },
                { DHGServer.newFactory(BuiltinDHFactories.ecdhp256), new ECDHNistP.Factory256() },
                { DHGServer.newFactory(BuiltinDHFactories.ecdhp384), new ECDHNistP.Factory384() },
                { DHGServer.newFactory(BuiltinDHFactories.ecdhp521), new ECDHNistP.Factory521() },
                { DHGServer.newFactory(BuiltinDHFactories.dhg1), DHGroups.Group1SHA1() },
                { DHGServer.newFactory(BuiltinDHFactories.dhg14), DHGroups.Group14SHA1() },
                { DHGServer.newFactory(BuiltinDHFactories.dhg14_256), DHGroups.Group14SHA256() },
                { DHGServer.newFactory(BuiltinDHFactories.dhg15_512), DHGroups.Group15SHA512() },
                { DHGServer.newFactory(BuiltinDHFactories.dhg16_512), DHGroups.Group16SHA512() },
                { DHGServer.newFactory(BuiltinDHFactories.dhg17_512), DHGroups.Group17SHA512() },
                { DHGServer.newFactory(BuiltinDHFactories.dhg18_512), DHGroups.Group18SHA512() },
        });
    }

    @TestFactory
    public Stream<DynamicTest> keyExchangeTests() {
        return getParameters().stream().map(params -> {
            KeyExchangeFactory serverFactory = (KeyExchangeFactory) params[0];
            Factory.Named<net.schmizz.sshj.transport.kex.KeyExchange> clientFactory = (Factory.Named<net.schmizz.sshj.transport.kex.KeyExchange>) params[1];
            SingletonRandomFactory randomFactory = new SingletonRandomFactory(new JCERandom.Factory());

            return DynamicTest.dynamicTest(serverFactory.getName() + " <-> " + clientFactory.getName(), () -> {
                try (SshServerExtension fixture = new SshServerExtension(false)) {
                    for (int i = 0; i < 10; i++) {
                        logger.info("--> Attempt {}", i);
                        fixture.getServer().setKeyExchangeFactories(Collections.singletonList(serverFactory));
                        fixture.start();
                        Config config = new DefaultConfig();
                        config.setRandomFactory(randomFactory);
                        config.setKeyExchangeFactories(Collections.singletonList(clientFactory));

                        SSHClient sshClient = fixture.connectClient(fixture.setupClient(config));
                        assertThat("should be connected", sshClient.isConnected());
                        sshClient.disconnect();
                        fixture.stopClient();
                    };
                };
            });
        });
    }
}
