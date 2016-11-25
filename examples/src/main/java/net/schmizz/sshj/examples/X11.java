package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.direct.Session.Command;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import net.schmizz.sshj.common.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;

/** This example demonstrates how forwarding X11 connections from a remote host can be accomplished. */
public class X11 {

    public static void main(String... args)
            throws IOException, InterruptedException {
        final SSHClient ssh = new SSHClient();

        // Compression makes X11 more feasible over slower connections
        // ssh.useCompression();

        ssh.loadKnownHosts();

        /*
        * NOTE: Forwarding incoming X connections to localhost:6000 only works if X is started without the
        * "-nolisten tcp" option (this is usually not the default for good reason)
        */
        ssh.registerX11Forwarder(new SocketForwardingConnectListener(new InetSocketAddress("localhost", 6000)));

        ssh.connect("localhost");
        try {

            ssh.authPublickey(System.getProperty("user.name"));

            Session sess = ssh.startSession();

            /*
            * It is recommendable to send a fake cookie, and in your ConnectListener when a connection comes in replace
            * it with the real one. But here simply one from `xauth list` is being used.
            */
            sess.reqX11Forwarding("MIT-MAGIC-COOKIE-1", "b0956167c9ad8f34c8a2788878307dc9", 0);

            final Command cmd = sess.exec("/usr/X11/bin/xcalc");

            new StreamCopier(cmd.getInputStream(), System.out, LoggerFactory.DEFAULT).spawn("stdout");
            new StreamCopier(cmd.getErrorStream(), System.err, LoggerFactory.DEFAULT).spawn("stderr");

            // Wait for session & X11 channel to get closed
            ssh.getConnection().join();

        } finally {
            ssh.disconnect();
        }
    }
}
