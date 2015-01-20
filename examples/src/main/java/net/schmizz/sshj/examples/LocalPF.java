/**
 * Copyright 2009 sshj contributors
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
package net.schmizz.sshj.examples;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder;

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
            final LocalPortForwarder.Parameters params
                    = new LocalPortForwarder.Parameters("0.0.0.0", 8080, "google.com", 80);
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
