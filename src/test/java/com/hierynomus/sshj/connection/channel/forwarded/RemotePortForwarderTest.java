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
import com.hierynomus.sshj.test.SshFixture;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class RemotePortForwarderTest {
    private static final Logger log = LoggerFactory.getLogger(RemotePortForwarderTest.class);

    private static final PortRange RANGE = new PortRange(9000, 9999);
    private static final InetSocketAddress HTTP_SERVER_SOCKET_ADDR = new InetSocketAddress("127.0.0.1", 8080);

    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public HttpServer httpServer = new HttpServer();

    @Before
    public void setUp() throws IOException {
        fixture.getServer().setForwardingFilter(new AcceptAllForwardingFilter());
        File file = httpServer.getDocRoot().newFile("index.html");
        FileUtil.writeToFile(file, "<html><head/><body><h1>Hi!</h1></body></html>");
    }

    @Test
    public void shouldHaveWorkingHttpServer() throws IOException {
        // Just to check that we have a working http server...
        assertThat(httpGet("127.0.0.1", 8080), equalTo(200));
    }

    @Test
    public void shouldDynamicallyForwardPortForLocalhost() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "127.0.0.1", new SinglePort(0));
        assertThat(httpGet("127.0.0.1", bind.getPort()), equalTo(200));
    }

    @Test
    public void shouldDynamicallyForwardPortForAllIPv4() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "0.0.0.0", new SinglePort(0));
        assertThat(httpGet("127.0.0.1", bind.getPort()), equalTo(200));
    }

    @Test
    public void shouldDynamicallyForwardPortForAllProtocols() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "", new SinglePort(0));
        assertThat(httpGet("127.0.0.1", bind.getPort()), equalTo(200));
    }

    @Test
    public void shouldForwardPortForLocalhost() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "127.0.0.1", RANGE);
        assertThat(httpGet("127.0.0.1", bind.getPort()), equalTo(200));
    }

    @Test
    public void shouldForwardPortForAllIPv4() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "0.0.0.0", RANGE);
        assertThat(httpGet("127.0.0.1", bind.getPort()), equalTo(200));
    }

    @Test
    public void shouldForwardPortForAllProtocols() throws IOException {
        SSHClient sshClient = getFixtureClient();
        RemotePortForwarder.Forward bind = forwardPort(sshClient, "", RANGE);
        assertThat(httpGet("127.0.0.1", bind.getPort()), equalTo(200));
    }

    private RemotePortForwarder.Forward forwardPort(SSHClient sshClient, String address, PortRange portRange) throws IOException {
        while (true) {
            try {
                RemotePortForwarder.Forward forward = sshClient.getRemotePortForwarder().bind(
                        // where the server should listen
                        new RemotePortForwarder.Forward(address, portRange.nextPort()),
                        // what we do with incoming connections that are forwarded to us
                        new SocketForwardingConnectListener(HTTP_SERVER_SOCKET_ADDR));

                return forward;
            } catch (ConnectionException ce) {
                if (!portRange.hasNext()) {
                    throw ce;
                }
            }
        }
    }

    private int httpGet(String server, int port) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        String urlString = "http://" + server + ":" + port;
        log.info("Trying: GET " + urlString);
        HttpResponse execute = client.execute(new HttpGet(urlString));
        return execute.getStatusLine().getStatusCode();
    }

    private SSHClient getFixtureClient() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("jeroen", "jeroen");
        return sshClient;
    }

    private static class PortRange {
        private int upper;
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
