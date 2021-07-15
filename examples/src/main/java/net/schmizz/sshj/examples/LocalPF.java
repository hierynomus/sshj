package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder;
import net.schmizz.sshj.connection.channel.direct.Parameters;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;

/**
 * This example demonstrates local port forwarding, i.e. when we listen on a particular address and port; and forward
 * all incoming connections to SSH server which further forwards them to a specified address and port.
 */
public class LocalPF {

    public static void main(String... args)
            throws IOException {
        SSHClient ssh = new SSHClient();

        ssh.loadKnownHosts();

        ssh.connect("localhost");
        try {

            ssh.authPublickey(System.getProperty("user.name"));

            /*
            * _We_ listen on localhost:8080 and forward all connections on to server, which then forwards it to
            * google.com:80
            */
            final Parameters params
                    = new Parameters("0.0.0.0", 8080, "google.com", 80);
            final ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress(params.getLocalHost(), params.getLocalPort()));
            try {
                ssh.newLocalPortForwarder(params, ss).listen();
            } finally {
                ss.close();
            }

        } finally {
            ssh.disconnect();
        }
    }

}
