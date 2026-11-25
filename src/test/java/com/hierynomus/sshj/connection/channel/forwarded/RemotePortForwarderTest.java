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
import com.hierynomus.sshj.test.LogCapture;
import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class RemotePortForwarderTest {
    private static final PortRange RANGE = new PortRange(9000, 9999);
    private static final String LOCALHOST = "127.0.0.1";
    private static final String URL_FORMAT = "http://%s:%d";

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @RegisterExtension
    public HttpServer httpServer = new HttpServer();

    @BeforeEach
    public void setUp() {
        fixture.getServer().setForwardingFilter(new AcceptAllForwardingFilter());
    }

    @Test
    public void shouldHaveWorkingHttpServer() throws IOException {
        final URI serverUrl = httpServer.getServerUrl();

        assertEquals(HttpURLConnection.HTTP_NOT_FOUND, httpGet(serverUrl.getHost(), serverUrl.getPort()));
    }

    @Test
    public void shouldDynamicallyForwardPortForLocalhost() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, LOCALHOST, new SinglePort(0));
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
        RemotePortForwarder.Forward bind = forwardPort(sshClient, LOCALHOST, RANGE);
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

    @Test
    @Timeout(30_000)
    public void shouldNotLogErrorsWhenForwardedPeerClosesWhileBackendIsIdle() throws Exception {
        // Regression test for #1048: when the channel side reaches EOF the forwarded socket must be
        // half-closed (shutdownOutput), not fully closed. A full close wakes the still-running
        // soc2chan copy - blocked reading the idle backend socket - with "SocketException: Socket
        // closed", which StreamCopier and Promise then log at ERROR for a normal connection close.
        //
        // The backend is a raw TCP server that sends a fixed reply and then, once its input reaches
        // EOF (the forwarded socket's half-close), closes its side so both copy directions finish.
        final byte[] reply = new byte[256 * 1024];
        new Random(42).nextBytes(reply);

        try (ServerSocket backend = new ServerSocket(0, 0, InetAddress.getByName(LOCALHOST))) {
            Thread backendThread = new Thread(() -> {
                try (Socket s = backend.accept()) {
                    InputStream bin = s.getInputStream();
                    s.getOutputStream().write(reply);
                    s.getOutputStream().flush();
                    while (bin.read() != -1) {
                        // keep the connection (and soc2chan) alive until our input is half-closed
                    }
                } catch (IOException ignored) {
                }
            }, "raw-backend");
            backendThread.setDaemon(true);
            backendThread.start();

            try (LogCapture logs = LogCapture.attachTo("net.schmizz")) {
                SSHClient sshClient = getFixtureClient();
                RemotePortForwarder.Forward bind = sshClient.getRemotePortForwarder().bind(
                        new RemotePortForwarder.Forward(LOCALHOST, 0),
                        new SocketForwardingConnectListener(new InetSocketAddress(LOCALHOST, backend.getLocalPort())));

                int totalRead = 0;
                try (Socket peer = new Socket(LOCALHOST, bind.getPort())) {
                    peer.setSoTimeout(20_000);
                    peer.getOutputStream().write("ping".getBytes(StandardCharsets.US_ASCII));
                    peer.getOutputStream().flush();

                    InputStream in = peer.getInputStream();
                    byte[] buf = new byte[8192];
                    try {
                        while (totalRead < reply.length) {
                            int n = in.read(buf);
                            if (n == -1) {
                                break;
                            }
                            totalRead += n;
                        }
                    } catch (IOException truncatedByFullClose) {
                        // The pre-fix full close of the backend socket truncates the relayed reply.
                    }
                    // Full reply received; close normally -> channel EOF -> chan2soc EOF.
                }

                sshClient.getConnection().join(); // wait for the forwarded channel to be torn down

                assertThat(totalRead).isEqualTo(reply.length);
                assertThat(logs.errorsFrom(StreamCopier.class, Promise.class)).isEmpty();
            }
        }
    }

    private void assertHttpGetSuccess(final RemotePortForwarder.Forward bind) throws IOException {
        final String bindAddress = bind.getAddress();
        final String address = bindAddress.isEmpty() ? LOCALHOST : bindAddress;
        final int port = bind.getPort();
        assertEquals(HttpURLConnection.HTTP_NOT_FOUND, httpGet(address, port));
    }

    private RemotePortForwarder.Forward forwardPort(SSHClient sshClient, String address, PortRange portRange) throws IOException {
        while (true) {
            final URI serverUrl = httpServer.getServerUrl();
            final InetSocketAddress serverAddress = new InetSocketAddress(serverUrl.getHost(), serverUrl.getPort());
            try {
                return sshClient.getRemotePortForwarder().bind(
                        // where the server should listen
                        new RemotePortForwarder.Forward(address, portRange.nextPort()),
                        // what we do with incoming connections that are forwarded to us
                        new SocketForwardingConnectListener(serverAddress));
            } catch (ConnectionException ce) {
                if (!portRange.hasNext()) {
                    throw ce;
                }
            }
        }
    }

    private int httpGet(final String address, final int port) throws IOException {
        final URL url = new URL(String.format(URL_FORMAT, address, port));
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
