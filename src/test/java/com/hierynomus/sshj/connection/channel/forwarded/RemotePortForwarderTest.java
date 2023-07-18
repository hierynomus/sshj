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
package com.hierynomus.sshj.connection.channel.forwarded;

import com.hierynomus.sshj.test.HttpServer;
import com.hierynomus.sshj.test.SshServerExtension;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RemotePortForwarderTest {
    private static final PortRange RANGE = new PortRange(9000, 9999);
    private static final String LOCALHOST = "127.0.0.1";
    private static final String LOCALHOST_URL_FORMAT = "http://127.0.0.1:%d";
    private static final InetSocketAddress HTTP_SERVER_SOCKET_ADDR = new InetSocketAddress(LOCALHOST, 8080);

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @RegisterExtension
    public HttpServer httpServer = new HttpServer();

    @BeforeEach
    public void setUp() throws IOException {
        fixture.getServer().setForwardingFilter(new AcceptAllForwardingFilter());
        File file = Files.createFile(httpServer.getDocRoot().toPath().resolve("index.html")).toFile();
        FileUtil.writeToFile(file, "<html><head/><body><h1>Hi!</h1></body></html>");
    }

    @Test
    public void shouldHaveWorkingHttpServer() throws IOException {
        assertEquals(200, httpGet(8080));
    }

    @Test
    public void shouldDynamicallyForwardPortForLocalhost() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "127.0.0.1", new SinglePort(0));
        assertHttpGetSuccess(bind);
    }

    @Test
    public void shouldDynamicallyForwardPortForAllIPv4() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "0.0.0.0", new SinglePort(0));
        assertHttpGetSuccess(bind);
    }

    @Test
    public void shouldDynamicallyForwardPortForAllProtocols() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "", new SinglePort(0));
        assertHttpGetSuccess(bind);
    }

    @Test
    public void shouldForwardPortForLocalhost() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "127.0.0.1", RANGE);
        assertHttpGetSuccess(bind);
    }

    @Test
    public void shouldForwardPortForAllIPv4() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "0.0.0.0", RANGE);
        assertHttpGetSuccess(bind);
    }

    @Test
    public void shouldForwardPortForAllProtocols() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "", RANGE);
        assertHttpGetSuccess(bind);
    }

    private void assertHttpGetSuccess(final RemotePortForwarder.Forward bind) throws IOException {
        assertEquals(200, httpGet(bind.getPort()));
    }

    private RemotePortForwarder.Forward forwardPort(SSHClient sshClient, String address, PortRange portRange) throws IOException {
        while (true) {
            try {
                return sshClient.getRemotePortForwarder().bind(
                        // where the server should listen
                        new RemotePortForwarder.Forward(address, portRange.nextPort()),
                        // what we do with incoming connections that are forwarded to us
                        new SocketForwardingConnectListener(HTTP_SERVER_SOCKET_ADDR));
            } catch (ConnectionException ce) {
                if (!portRange.hasNext()) {
                    throw ce;
                }
            }
        }
    }

    private int httpGet(final int port) throws IOException {
        final URL url = new URL(String.format(LOCALHOST_URL_FORMAT, port));
        final HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        urlConnection.setConnectTimeout(3000);
        urlConnection.setRequestMethod("GET");
        return urlConnection.getResponseCode();
    }

    private SSHClient getFixtureClient() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("jeroen", "jeroen");
        return sshClient;
    }

    private static class PortRange {
        private final int upper;
        private int current;

        public PortRange(int lower, int upper) {
            this.upper = upper;
            this.current = lower;
        }

        public int nextPort() {
            if (current < upper) {
                return current++;
            }
            throw new IllegalStateException("Out of ports!");
        }

        public boolean hasNext() {
            return current < upper;
        }
    }

    private static class SinglePort extends PortRange {
        private final int port;

        public SinglePort(int port) {
            super(port, port);
            this.port = port;
        }

        @Override
        public int nextPort() {
            return port;
        }


    }

}
