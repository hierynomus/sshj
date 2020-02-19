package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.DirectConnection;
import net.schmizz.sshj.connection.channel.direct.Session;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * This example demonstrates connecting via an intermediate "jump" server using a direct TCP/IP channel.
 */
public class Jump {
    public static void main(String... args)
            throws IOException {
        SSHClient firstHop = new SSHClient();

        firstHop.loadKnownHosts();

        firstHop.connect("localhost");
        try {

            firstHop.authPublickey(System.getProperty("user.name"));

            DirectConnection tunnel = firstHop.newDirectConnection("localhost", 22);

            SSHClient ssh = new SSHClient();
            try {
                ssh.loadKnownHosts();
                ssh.connectVia(tunnel);
                ssh.authPublickey(System.getProperty("user.name"));

                final Session session = ssh.startSession();
                try {
                    final Session.Command cmd = session.exec("ping -c 1 google.com");
                    System.out.println(IOUtils.readFully(cmd.getInputStream()).toString());
                    cmd.join(5, TimeUnit.SECONDS);
                    System.out.println("\n** exit status: " + cmd.getExitStatus());
                } finally {
                    session.close();
                }
            } finally {
                ssh.disconnect();
            }
        } finally {
            firstHop.disconnect();
        }
    }
}
