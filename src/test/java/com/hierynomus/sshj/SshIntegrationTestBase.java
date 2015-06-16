package com.hierynomus.sshj;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.net.ServerSocket;

public class SshIntegrationTestBase {
    public static final String hostkey = "src/test/resources/hostkey.pem";
    public static final String fingerprint = "ce:a7:c1:cf:17:3f:96:49:6a:53:1a:05:0b:ba:90:db";

    public static final String hostname = "localhost";

    protected SshServer server = null;

    @Before
    public void setupSshServer() throws IOException {
        server = SshServer.setUpDefaultServer();
        server.setPort(randomPort());
        configureSshServer();
        server.start();
    }

    @After
    public void stopSshServer() throws Exception {
        server.stop();
    }

    protected void configureSshServer() {
        server.setKeyPairProvider(new FileKeyPairProvider(new String[]{hostkey}));
        server.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session) {
                return username.equals(password);
            }
        });
    }

    private int randomPort() {
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

}

