/*
 * Copyright 2010 Shikhar Bhushan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package examples;

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

//    static {
//        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("%d [%-15.15t] %-5p %-30.30c{1} - %m%n")));
//    }

    public static void main(String... args)
            throws IOException {
        SSHClient client = new SSHClient();
        client.loadKnownHosts();

        client.connect("localhost");
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
                    new SocketForwardingConnectListener(new InetSocketAddress("google.com", 80)
                    ));

            client.getTransport()
                    .setHeartbeatInterval(30);

            // Something to hang on to so that the forwarding stays
            client.getTransport().join();

        } finally {
            client.disconnect();
        }
    }

}
