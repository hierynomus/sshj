package com.hierynomus.sshj;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.util.gss.BogusGSSAuthenticator;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.junit.rules.ExternalResource;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Can be used as a rule to ensure the server is teared down after each test.
 */
public class SshFixture extends ExternalResource {
    public static final String hostkey = "src/test/resources/hostkey.pem";
    public static final String fingerprint = "ce:a7:c1:cf:17:3f:96:49:6a:53:1a:05:0b:ba:90:db";

    private SshServer server = defaultSshServer();
    private SSHClient client = null;
    private AtomicBoolean started = new AtomicBoolean(false);
    private boolean autoStart = true;

    public SshFixture(boolean autoStart) {
        this.autoStart = autoStart;
    }

    public SshFixture() {
    }

    @Override
    protected void before() throws Throwable {
        if (autoStart) {
            start();
        }
    }

    @Override
    protected void after() {
        stopClient();
        stopServer();
    }

    public void start() throws IOException {
        server.start();
        started.set(true);
    }

    public SSHClient setupConnectedDefaultClient() throws IOException {
        return connectClient(setupDefaultClient());
    }

    public SSHClient setupDefaultClient() {
        return setupClient(new DefaultConfig());
    }

    public SSHClient setupClient(Config config) {
        if (client == null) {
            client = new SSHClient(config);
            client.addHostKeyVerifier(fingerprint);
        }
        return client;
    }

    public SSHClient getClient() {
        if (client != null) {
            return client;
        }

        throw new IllegalStateException("First call one of the setup*Client methods");
    }

    public SSHClient connectClient(SSHClient client) throws IOException {
        client.connect(server.getHost(), server.getPort());
        return client;
    }

    private SshServer defaultSshServer() {
        SshServer sshServer = SshServer.setUpDefaultServer();
        sshServer.setPort(randomPort());
        sshServer.setKeyPairProvider(new FileKeyPairProvider(new String[]{hostkey}));
        sshServer.setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session) {
                return username.equals(password);
            }
        });
        sshServer.setGSSAuthenticator(new BogusGSSAuthenticator());
        sshServer.setSubsystemFactories(Collections.<NamedFactory<Command>>singletonList(new SftpSubsystem.Factory()));
        return sshServer;
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

    public void stopClient() {
        if (client != null && client.isConnected()) {
            try {
                client.disconnect();
            } catch (IOException e) {
                // Ignore
            } finally {
                client = null;
            }
        } else if (client != null) {
            client = null;
        }
    }

    public void stopServer() {
        if (started.get()) {
            try {
                server.stop();
            } catch (InterruptedException e) {
                // ignore
            }
        }
    }
}
