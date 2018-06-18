package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.direct.Session.Command;

import java.io.Console;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/** This examples demonstrates how a remote command can be executed. */
public class Exec {
    private static final Console con = System.console();

    public static void main(String... args)
            throws IOException {
        final SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect("localhost");
        Session session = null;
        try {
            ssh.authPublickey(System.getProperty("user.name"));
            session = ssh.startSession();
            final Command cmd = session.exec("ping -c 1 google.com");
            con.writer().print(IOUtils.readFully(cmd.getInputStream()).toString());
            cmd.join(5, TimeUnit.SECONDS);
            con.writer().print("\n** exit status: " + cmd.getExitStatus());
        } finally {
            try {
                if (session != null) {
                    session.close();
                }
            } catch (IOException e) {
                // Do Nothing   
            }
            
            ssh.disconnect();
        }
    }

}
