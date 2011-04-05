/*
 * Copyright 2010, 2011 sshj contributors
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
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.direct.Session.Command;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;

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

            new StreamCopier("stdout", cmd.getInputStream(), System.out).start();
            new StreamCopier("stderr", cmd.getErrorStream(), System.err).start();

            // Wait for session & X11 channel to get closed
            ssh.getConnection().join();

        } finally {
            ssh.disconnect();
        }
    }
}