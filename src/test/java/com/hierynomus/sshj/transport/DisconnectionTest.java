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
package com.hierynomus.sshj.transport;

import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.transport.DisconnectListener;
import net.schmizz.sshj.transport.TransportException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DisconnectionTest {
    private AtomicBoolean disconnected = null;

    @Rule
    public SshFixture fixture = new SshFixture();

    @Before
    public void setupFlag() throws IOException {
        disconnected = new AtomicBoolean(false);
        // Initialize the client
        SSHClient defaultClient = fixture.setupDefaultClient();
        defaultClient.getTransport().setDisconnectListener(new DisconnectListener() {
            @Override
            public void notifyDisconnect(DisconnectReason reason, String message) {
                disconnected.set(true);
            }
        });
        fixture.connectClient(defaultClient);
    }

    private boolean joinToClientTransport(int seconds) {
        try {
            fixture.getClient().getTransport().join(seconds, TimeUnit.SECONDS);
            return true;
        } catch (TransportException ignored) {
            return false;
        }
    }

    @Test
    public void listenerNotifiedOnClientDisconnect()
            throws IOException {
        fixture.getClient().disconnect();
        assertTrue(disconnected.get());
    }

    @Test
    public void listenerNotifiedOnServerDisconnect()
            throws InterruptedException, IOException {
        fixture.stopServer();
        joinToClientTransport(2);
        assertTrue(disconnected.get());
    }

    @Test
    public void joinNotifiedOnClientDisconnect()
            throws IOException {
        fixture.getClient().disconnect();
        assertTrue(joinToClientTransport(2));
    }

    @Test
    public void joinNotifiedOnServerDisconnect()
            throws TransportException, InterruptedException {
        fixture.stopServer();
        assertFalse(joinToClientTransport(2));
    }

    @Test
    public void shouldNotThrowTimeoutOnDisconnect() throws IOException {
        fixture.getClient().authPassword("u", "u");
        Session session = fixture.getClient().startSession();
        session.allocateDefaultPTY();
        Session.Shell shell = session.startShell();

        session.close();
        fixture.getClient().disconnect();
    }
}
