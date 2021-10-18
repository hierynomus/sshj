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
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder;
import net.schmizz.sshj.connection.channel.direct.Parameters;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class LocalPortForwarderTest {
    private static final Logger log = LoggerFactory.getLogger(LocalPortForwarderTest.class);

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
    public void shouldHaveHttpServerThatClosesConnectionAfterResponse() throws IOException {
        // Just to check that the test server does close connections before we try through the forwarder...
        httpGetAndAssertConnectionClosedByServer(8080);
    }

    @Test(timeout = 10_000)
    public void shouldCloseConnectionWhenRemoteServerClosesConnection() throws IOException {
        SSHClient sshClient = getFixtureClient();

        ServerSocket serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress("0.0.0.0", 12345));
        LocalPortForwarder localPortForwarder = sshClient.newLocalPortForwarder(new Parameters("0.0.0.0", 12345, "localhost", 8080), serverSocket);
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
        System.out.println("HTTP GET to port: " + port);
        try (Socket socket = new Socket("localhost", port)) {
            // Send a basic HTTP GET
            // It returns 400 Bad Request because it's missing a bunch of info, but the HTTP response doesn't matter, we just want to test the connection closing.
            OutputStream outputStream = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(outputStream);
            writer.println("GET / HTTP/1.1");
            writer.println("");
            writer.flush();

            // Read the HTTP response
            InputStream inputStream = socket.getInputStream();
            InputStreamReader reader = new InputStreamReader(inputStream);
            int buf = -2;
            while (true) {
                buf = reader.read();
                System.out.print((char)buf);
                if (buf == -1) {
                    break;
                }
            }

            // Attempt to read more. If the server has closed the connection this will return -1
            int read = inputStream.read();

            // Assert input stream was closed by server.
            Assert.assertEquals(-1, read);
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
}
