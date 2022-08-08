package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder.Forward;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * This example demonstrates remote port forwarding i.e. when the remote host is made to listen on a specific address
 * and port; and forwards us incoming connections.
 */
public class RemotePF {

    public static void main(String... args)
            throws IOException {
        SSHClient client = new SSHClient();
        client.loadKnownHosts();

        client.connect("localhost");
        client.getConnection().getKeepAlive().setKeepAliveInterval(5);
        try {

            client.authPublickey(System.getProperty("user.name"));

            /*
            * We make _server_ listen on port 8080, which forwards all connections to us as a channel, and we further
            * forward all such channels to google.com:80
            */
            client.getRemotePortForwarder().bind(
                    // where the server should listen
                    new Forward(8080),
                    // what we do with incoming connections that are forwarded to us
                    new SocketForwardingConnectListener(new InetSocketAddress("google.com", 80)));

            // Something to hang on to so that the forwarding stays
            client.getTransport().join();

        } finally {
            client.disconnect();
        }
    }

}
