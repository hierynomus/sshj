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
package com.hierynomus.sshj.test;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import org.apache.sshd.server.SshServer;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public abstract class BaseAlgorithmTest {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Rule
    public SshFixture fixture = new SshFixture(false);

    @After
    public void stopServer() {
        fixture.stopServer();
    }

    @Test
    public void shouldVerifyAlgorithm() throws IOException {
        attempt(100);
    }

    private void attempt(int times) throws IOException {
        for (int i = 0; i < times; i++) {
            logger.info("--> Attempt {}", i);
            verify();
        }
    }

    private void verify() throws IOException {
        configureServer(fixture.getServer());
        fixture.start();
        Config config = getClientConfig(new DefaultConfig());
        SSHClient sshClient = fixture.connectClient(fixture.setupClient(config));
        assertThat("should be connected", sshClient.isConnected());
        sshClient.disconnect();
//        fixture.stopServer();
        fixture.stopClient();
    }

    protected abstract Config getClientConfig(DefaultConfig defaultConfig);

    protected abstract void configureServer(SshServer server);
}
