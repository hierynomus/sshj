/*
 * Copyright (C)2009 - SSHJ Contributors
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
package com.hierynomus.sshj.test;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.util.gss.BogusGSSAuthenticator;
import org.apache.sshd.common.keyprovider.ClassLoadableResourceKeyPairProvider;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Can be used as a rule to ensure the server is teared down after each test.
 */
public class SshServerExtension implements BeforeEachCallback, AfterEachCallback, Closeable {
    public static final String hostkey = "hostkey.pem";
    public static final String fingerprint = "ce:a7:c1:cf:17:3f:96:49:6a:53:1a:05:0b:ba:90:db";
    public static final String listCommand = OsUtils.isWin32() ? "cmd.exe /C dir" : "ls";

    private final SshServer server = defaultSshServer();
    private SSHClient client = null;
    private final AtomicBoolean started = new AtomicBoolean(false);
    private boolean autoStart = true;

    public SshServerExtension(boolean autoStart) {
        this.autoStart = autoStart;
    }

    public SshServerExtension() {
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        close();
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        if (autoStart) {
            start();
        }
    }


    @Override
    public void close() throws IOException {
        stopClient();
        stopServer();
    }

    public void start() throws IOException {
        if (!started.getAndSet(true)) {
            server.start();
        }
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

    /**
     * create a new uncached client
     */
    public SSHClient createClient(Config config) {
        SSHClient client = new SSHClient(config);
        client.addHostKeyVerifier(fingerprint);
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
        ClassLoadableResourceKeyPairProvider fileKeyPairProvider = new ClassLoadableResourceKeyPairProvider(hostkey);
        sshServer.setKeyPairProvider(fileKeyPairProvider);
        sshServer.setPasswordAuthenticator((username, password, session) -> username.equals(password));
        sshServer.setGSSAuthenticator(new BogusGSSAuthenticator());
        sshServer.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
        ScpCommandFactory commandFactory = new ScpCommandFactory();
        commandFactory.setDelegateCommandFactory((session, command) -> new ProcessShellFactory(command, command.split(" ")).createShell(session));
        sshServer.setCommandFactory(commandFactory);
        sshServer.setShellFactory(new ProcessShellFactory(listCommand, listCommand.split(" ")));
        return sshServer;
    }

    private int randomPort() {
        try {
            try (final ServerSocket s = new ServerSocket(0)) {
                return s.getLocalPort();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void stopClient() {
        if (client != null && client.isConnected()) {
            try {
                client.disconnect();
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                client = null;
            }
        } else if (client != null) {
            client = null;
        }
    }

    public void stopServer() {
        if (started.getAndSet(false)) {
            try {
                server.stop(true);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public SshServer getServer() {
        return server;
    }
}
