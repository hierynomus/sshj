package net.schmizz.sshj;

import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;

public class SshKeepAlive {

    public static void main(String[] args) throws IOException, InterruptedException {
        Config config = new DefaultConfig();
        config.setKeepAliveProvider(KeepAliveProvider.KEEP_ALIVE);
        SSHClient client = new SSHClient(config);
        client.conn.getKeepAlive().setKeepAliveInterval(5);
        client.addHostKeyVerifier(new PromiscuousVerifier());
        client.connect("172.16.37.129", 22);
        client.authPassword("jeroen", "jeroen");
        new CountDownLatch(1).await();
    }
}
