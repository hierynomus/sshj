package net.schmizz.sshj.examples;

import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;

/** This examples demonstrates how to setup keep-alive to detect connection dropping. */
public class KeepAlive {

    public static void main(String... args)
            throws IOException, InterruptedException {
        DefaultConfig defaultConfig = new DefaultConfig();
        defaultConfig.setKeepAliveProvider(KeepAliveProvider.KEEP_ALIVE);
        final SSHClient ssh = new SSHClient(defaultConfig);
        try {
            ssh.addHostKeyVerifier(new PromiscuousVerifier());
            // Set interval to enable keep-alive before connecting
            ssh.getConnection().getKeepAlive().setKeepAliveInterval(5);
            ssh.connect(args[0]);
            ssh.authPassword(args[1], args[2]);
            Session session = ssh.startSession();
            session.allocateDefaultPTY();
            new CountDownLatch(1).await();
            try {
                session.allocateDefaultPTY();
            } finally {
                session.close();
            }
        } finally {
            ssh.disconnect();
        }
    }
}
