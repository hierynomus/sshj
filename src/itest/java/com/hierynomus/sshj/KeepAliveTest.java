package com.hierynomus.sshj;

import net.schmizz.keepalive.BoundedKeepAliveProvider;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;

import java.util.ArrayList;
import java.util.List;

public class KeepAliveTest {
    @Container
    SshdContainer sshd = new SshdContainer(SshdContainer.Builder
            .defaultBuilder()
            .withAllKeys()
            .withPackages("iptables")
            .withPrivileged(true));

    @Test
    void testKeepAlive() throws Exception {
        sshd.start();

        Config config = new DefaultConfig();
        BoundedKeepAliveProvider p = new BoundedKeepAliveProvider(LoggerFactory.DEFAULT, 4);
        p.setKeepAliveInterval(1);
        p.setMaxKeepAliveCount(1);
        config.setKeepAliveProvider(p);
        List<SSHClient> clients = new ArrayList<>();
        for (int i=0; i<10; i++) {
            SSHClient c = new SSHClient(config);
            c.addHostKeyVerifier(new PromiscuousVerifier());
            c.connect("127.0.0.1", sshd.getFirstMappedPort());
            c.authPassword("sshj", "ultrapassword");
            var sess = c.startSession();
            sess.allocateDefaultPTY();
            clients.add(c);
        }

        for (SSHClient client : clients) {
            Assertions.assertTrue(client.isConnected());
        }

        var res = sshd.execInContainer("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP");
        Assertions.assertEquals(0, res.getExitCode());
        // wait for keepalive to take action
        Thread.sleep(2000);

        for (SSHClient client : clients) {
            Assertions.assertFalse(client.isConnected());
        }

        p.shutdown();
    }
}
