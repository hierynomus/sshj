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
package net.schmizz.sshj.util;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;

import java.io.IOException;
import java.net.ServerSocket;


public class BasicFixture {

    public static final String hostkey = "src/test/resources/hostkey.pem";
    public static final String fingerprint = "ce:a7:c1:cf:17:3f:96:49:6a:53:1a:05:0b:ba:90:db";

    public static final String hostname = "localhost";
    public final int port = gimmeAPort();

    private SSHClient client;
    private SshServer server;

    private boolean clientRunning = false;
    private boolean serverRunning = false;

    private static int gimmeAPort() {
        try {
            ServerSocket s = null;
            try {
                s = new ServerSocket(0);
                return s.getLocalPort();
            } finally {
                if (s != null)
                    s.close();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void init()
            throws IOException {
        init(false);
    }

    public void init(boolean authenticate)
            throws IOException {
        startServer();
        startClient(authenticate);
    }

    public void done()
            throws InterruptedException, IOException {
        stopClient();
        stopServer();
    }

    public void startServer()
            throws IOException {
        server = SshServer.setUpDefaultServer();
        server.setPort(port);
        server.setKeyPairProvider(new FileKeyPairProvider(new String[]{hostkey}));
        server.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String u, String p, ServerSession s) {
                return false;
            }
        });
        server.start();
        serverRunning = true;
    }

    public void stopServer()
            throws InterruptedException {
        if (serverRunning) {
            server.stop();
            serverRunning = false;
        }
    }

    public SshServer getServer() {
        return server;
    }

    public void startClient(boolean authenticate)
            throws IOException {
        client = new SSHClient();
        client.addHostKeyVerifier(fingerprint);
        client.connect(hostname, port);
        if (authenticate)
            dummyAuth();
        clientRunning = true;
    }

    public void stopClient()
            throws IOException {
        if (clientRunning) {
            client.disconnect();
            clientRunning = false;
        }
    }

    public SSHClient getClient() {
        return client;
    }

    public void dummyAuth()
            throws UserAuthException, TransportException {
        server.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        client.authPassword("same", "same");
    }

}
