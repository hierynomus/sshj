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
import net.schmizz.sshj.xfer.FileSystemFile;

import java.io.IOException;

/** This example demonstrates downloading of a file over SCP from the SSH server.
 * NB: ensure that you have an SSH server running locally before running this example. */
public class SCPDownload {

    public static void main(String[] args)
            throws IOException {
        SSHClient ssh = new SSHClient();
        // ssh.useCompression(); // Can lead to significant speedup (needs JZlib in classpath)
        ssh.loadKnownHosts();
        ssh.connect("localhost");
        try {
            ssh.authPublickey(System.getProperty("user.name"));
            ssh.newSCPFileTransfer().download("test_file", new FileSystemFile("/tmp/"));
        } finally {
            ssh.disconnect();
        }
    }

}