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
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.direct.Session.Shell;
import net.schmizz.sshj.transport.verification.ConsoleKnownHostsVerifier;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;

import java.io.File;
import java.io.IOException;

/** A very rudimentary psuedo-terminal based on console I/O. */
class RudimentaryPTY {

    public static void main(String... args)
            throws IOException {

        final SSHClient ssh = new SSHClient();

        final File khFile = new File(OpenSSHKnownHosts.detectSSHDir(), "known_hosts");
        ssh.addHostKeyVerifier(new ConsoleKnownHostsVerifier(khFile, System.console()));

        ssh.connect("localhost");

        Shell shell = null;

        try {

            ssh.authPublickey(System.getProperty("user.name"));

            final Session session = ssh.startSession();
            session.allocateDefaultPTY();

            shell = session.startShell();

            new StreamCopier("stdout", shell.getInputStream(), System.out)
                    .bufSize(shell.getLocalMaxPacketSize())
                    .start();

            new StreamCopier("stderr", shell.getErrorStream(), System.err)
                    .bufSize(shell.getLocalMaxPacketSize())
                    .start();

            // Now make System.in act as stdin. To exit, hit Ctrl+D (since that results in an EOF on System.in)
            // This is kinda messy because java only allows console input after you hit return
            // But this is just an example... a GUI app could implement a proper PTY
            StreamCopier.copy(System.in, shell.getOutputStream(), shell.getRemoteMaxPacketSize(), true);

        } finally {

            if (shell != null)
                shell.close();
            ssh.disconnect();
        }
    }

}
