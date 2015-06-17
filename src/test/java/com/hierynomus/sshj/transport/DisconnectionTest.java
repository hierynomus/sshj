package com.hierynomus.sshj.transport;

import com.hierynomus.sshj.SshFixture;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.DisconnectReason;
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

}
