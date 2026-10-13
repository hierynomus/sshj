package com.hierynomus.sshj.keepalive;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.keepalive.BoundedKeepAliveProvider;
import net.schmizz.keepalive.KeepAlive;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.TransportException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

class EventuallyFailKeepAlive extends KeepAlive {
    // they can survive first 2 checks, and fail at 3rd
    int failAfter = 1;
    volatile int current = 0;

    protected EventuallyFailKeepAlive(ConnectionImpl conn, String name) {
        super(conn, name);
        setKeepAliveInterval(1);
    }

    @Override
    protected void doKeepAlive() throws TransportException, ConnectionException {
        current++;
        if (current > failAfter) {
            throw new ConnectionException("failed");
        }
    }
}

public class BoundedKeepAliveProviderTest {

    static BoundedKeepAliveProvider kp;
    static final DefaultConfig defaultConfig = new DefaultConfig();


    @BeforeAll
    static void setUpBeforeClass() throws Exception {

        kp = new BoundedKeepAliveProvider(LoggerFactory.DEFAULT, 2) {
            @Override
            public KeepAlive provide(ConnectionImpl connection) {
                return new EventuallyFailKeepAlive(connection, "test") {
                    @Override
                    public void startKeepAlive() {
                        monitor.register(this);
                    }
                };
            }
        };
    }

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    void testWithConnections(int numOfConnections) throws IOException, InterruptedException {
        List<SSHClient> clients = setupClients(numOfConnections);
        for (SSHClient client : clients) {
            fixture.connectClient(client);
        }
        // first two checks are ok
        Thread.sleep(1000);
        Assertions.assertTrue(clients.stream().allMatch(SSHClient::isConnected));

        // wait for 2nd check to take place, we wait additional 200ms for it to finish
        Thread.sleep(1200);
        Assertions.assertTrue(clients.stream().noneMatch(SSHClient::isConnected));
        Assertions.assertEquals(0, fixture.getServer().getActiveSessions().size());
    }

    @Test
    void testBoundedKeepAlive() throws IOException, InterruptedException {
        // 2 threads can handle 32 connections
        testWithConnections(32);
    }

    private List<SSHClient> setupClients(int numOfConnections) {
        List<SSHClient> clients = new ArrayList<>();
        defaultConfig.setKeepAliveProvider(kp);

        for (int i = 0; i < numOfConnections; i++) {
            final SSHClient sshClient = fixture.createClient(defaultConfig);
            clients.add(sshClient);
        }
        return clients;
    }
}
