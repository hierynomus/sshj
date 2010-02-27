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
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.PatternLayout;

/** This example demonstrates uploading of a file over SCP to the SSH server. */
public class MTTest {

    static {
        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("%d [%-15.15t] %-5p %-30.30c{1} - %m%n")));
    }

    public static void main(String[] args) throws Exception {
        final SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect("localhost");
        try {
            ssh.authPublickey(System.getProperty("user.name"));

            new Thread() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(1000);
                        // Compression = significant speedup for large file transfers on fast links
                        // present here to demo algorithm renegotiation - could have just put this before connect()
                        ssh.useCompression();
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                }
            }.start();

            ssh.newSCPFileTransfer().upload("/Users/shikhar/well", "/tmp/");
        } finally {
            ssh.disconnect();
        }
    }
}