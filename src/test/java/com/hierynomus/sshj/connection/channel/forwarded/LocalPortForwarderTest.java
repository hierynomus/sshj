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
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder;
import net.schmizz.sshj.connection.channel.direct.Parameters;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.*;
import java.net.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LocalPortForwarderTest {
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
        assertEquals(HttpURLConnection.HTTP_NOT_FOUND, httpGet());
    }

    @Test
    public void shouldHaveHttpServerThatClosesConnectionAfterResponse() throws IOException {
        // Just to check that the test server does close connections before we try through the forwarder...
        httpGetAndAssertConnectionClosedByServer(httpServer.getServerUrl().getPort());
    }

    @Test
    @Timeout(10_000)
    public void shouldCloseConnectionWhenRemoteServerClosesConnection() throws IOException {
        SSHClient sshClient = getFixtureClient();

        ServerSocket serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress("0.0.0.0", 12345));
        final int serverPort = httpServer.getServerUrl().getPort();
        LocalPortForwarder localPortForwarder = sshClient.newLocalPortForwarder(new Parameters("0.0.0.0", 12345, "localhost", serverPort), serverSocket);
        new Thread(() -> {
            try {
                localPortForwarder.listen();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }, "local port listener").start();

        // Test once to prove that the local HTTP connection is closed when the remote HTTP connection is closed.
        httpGetAndAssertConnectionClosedByServer(12345);

        // Test again to prove that the tunnel is still open, even after HTTP connection was closed.
        httpGetAndAssertConnectionClosedByServer(12345);
    }

    public static void httpGetAndAssertConnectionClosedByServer(int port) throws IOException {
        try (Socket socket = new Socket("localhost", port)) {
            // Send a basic HTTP GET
            // It returns 400 Bad Request because it's missing a bunch of info, but the HTTP response doesn't matter, we just want to test the connection closing.
            OutputStream outputStream = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(outputStream);
            writer.println("GET / HTTP/1.1\r\n");
            writer.println("");
            writer.flush();

            // Read the HTTP response
            InputStream inputStream = socket.getInputStream();
            InputStreamReader reader = new InputStreamReader(inputStream);
            int buf = -2;
            while (buf != -1) {
                buf = reader.read();
            }

            // Attempt to read more. If the server has closed the connection this will return -1
            int read = inputStream.read();

            // Assert input stream was closed by server.
            assertEquals(-1, read);
        }
    }

    private int httpGet() throws IOException {
        final URL url = httpServer.getServerUrl().toURL();
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
}
