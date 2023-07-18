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
package com.hierynomus.sshj.keepalive;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.keepalive.KeepAlive;
import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.UserAuthException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

public class KeepAliveThreadTerminationTest {

    private static final int KEEP_ALIVE_SECONDS = 1;

    private static final long STOP_SLEEP = 1500;

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @Test
    public void shouldNotStartThreadOnSetKeepAliveInterval() {
        final SSHClient sshClient = setupClient();

        final KeepAlive keepAlive = sshClient.getConnection().getKeepAlive();
        assertTrue(keepAlive.isDaemon());
        assertFalse(keepAlive.isAlive());
        assertEquals(Thread.State.NEW, keepAlive.getState());
    }

    @Test
    public void shouldStartThreadOnConnectAndInterruptOnDisconnect() throws IOException, InterruptedException {
        final SSHClient sshClient = setupClient();

        final KeepAlive keepAlive = sshClient.getConnection().getKeepAlive();
        assertTrue(keepAlive.isDaemon());
        assertEquals(Thread.State.NEW, keepAlive.getState());

        fixture.connectClient(sshClient);

        assertThrows(UserAuthException.class, () -> sshClient.authPassword("bad", "credentials"));

        assertEquals(Thread.State.TIMED_WAITING, keepAlive.getState());

        fixture.stopClient();
        Thread.sleep(STOP_SLEEP);

        assertFalse(keepAlive.isAlive());
        assertEquals(Thread.State.TERMINATED, keepAlive.getState());
    }

    private SSHClient setupClient() {
        final DefaultConfig defaultConfig = new DefaultConfig();
        defaultConfig.setKeepAliveProvider(KeepAliveProvider.KEEP_ALIVE);
        final SSHClient sshClient = fixture.setupClient(defaultConfig);
        sshClient.getConnection().getKeepAlive().setKeepAliveInterval(KEEP_ALIVE_SECONDS);
        return sshClient;
    }
}
