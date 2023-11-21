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

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder.Forward;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RemotePFPerformanceTest {

    private static final Logger log = LoggerFactory.getLogger(RemotePFPerformanceTest.class);

    @Test
    @Disabled
    public void startPF() throws IOException, InterruptedException {
        DefaultConfig config = new DefaultConfig();
        config.setMaxCircularBufferSize(16 * 1024 * 1024);
        SSHClient client = new SSHClient(config);
        client.loadKnownHosts();
        client.addHostKeyVerifier("5c:0c:8e:9d:1c:50:a9:ba:a7:05:f6:b1:2b:0b:5f:ba");

        client.getConnection().getKeepAlive().setKeepAliveInterval(5);
        client.connect("localhost");
        client.getConnection().getKeepAlive().setKeepAliveInterval(5);

        Object consumerReadyMonitor = new Object();
        ConsumerThread consumerThread = new ConsumerThread(consumerReadyMonitor);
        ProducerThread producerThread = new ProducerThread();
        try {

            client.authPassword(System.getenv().get("USERNAME"), System.getenv().get("PASSWORD"));

            /*
            * We make _server_ listen on port 8080, which forwards all connections to us as a channel, and we further
            * forward all such channels to google.com:80
            */
            client.getRemotePortForwarder().bind(
                    // where the server should listen
                    new Forward(8888),
                    // what we do with incoming connections that are forwarded to us
                    new SocketForwardingConnectListener(new InetSocketAddress("localhost", 12345)));

            consumerThread.start();
            synchronized (consumerReadyMonitor) {
                consumerReadyMonitor.wait();
            }
            producerThread.start();

            // Wait for consumer to finish receiving data.
            synchronized (consumerReadyMonitor) {
                consumerReadyMonitor.wait();
            }

        } finally {
            producerThread.interrupt();
            consumerThread.interrupt();
            client.disconnect();
        }
    }

    private static class ConsumerThread extends Thread {
        private final Object consumerReadyMonitor;

        private ConsumerThread(Object consumerReadyMonitor) {
            super("Consumer");
            this.consumerReadyMonitor = consumerReadyMonitor;
        }

        @Override
        public void run() {
            try (ServerSocket serverSocket = new ServerSocket(12345)) {
                synchronized (consumerReadyMonitor) {
                    consumerReadyMonitor.notifyAll();
                }
                try (Socket acceptedSocket = serverSocket.accept()) {
                    InputStream in = acceptedSocket.getInputStream();
                    int numRead;
                    byte[] buf = new byte[40000];
                    //byte[] buf = new byte[255 * 4 * 1000];
                    byte expectedNext = 1;
                    while ((numRead = in.read(buf)) != 0) {
                        if (Thread.interrupted()) {
                            log.info("Consumer thread interrupted");
                            return;
                        }
                        log.info(String.format("Read %d characters; values from %d to %d", numRead, buf[0], buf[numRead - 1]));
                        if (buf[numRead - 1] == 0) {
                            verifyData(buf, numRead - 1, expectedNext);
                            break;
                        }
                        expectedNext = verifyData(buf, numRead, expectedNext);
                        // Slow down consumer to test buffering.
                        Thread.sleep(Long.parseLong(System.getenv().get("DELAY_MS")));
                    }
                    log.info("Consumer read end of stream value: " + numRead);
                    synchronized (consumerReadyMonitor) {
                        consumerReadyMonitor.notifyAll();
                    }
                }
            } catch (Exception e) {
                synchronized (consumerReadyMonitor) {
                    consumerReadyMonitor.notifyAll();
                }
                e.printStackTrace();
            }
        }

        private byte verifyData(byte[] buf, int numRead, byte expectedNext) {
            for (int i = 0; i < numRead; ++i) {
                if (buf[i] != expectedNext) {
                    fail("Expected buf[" + i + "]=" + buf[i] + " to be " + expectedNext);
                }
                if (++expectedNext == 0) {
                    expectedNext = 1;
                }
            }
            return expectedNext;
        }
    }

    private static class ProducerThread extends Thread {
        private ProducerThread() {
            super("Producer");
        }

        @Override
        public void run() {
            try (Socket clientSocket = new Socket("127.0.0.1", 8888);
                 OutputStream writer = clientSocket.getOutputStream()) {
                byte[] buf = getData();
                assertEquals(buf[0], 1);
                assertEquals(buf[buf.length - 1], -1);
                for (int i = 0; i < 1000; ++i) {
                    writer.write(buf);
                    if (Thread.interrupted()) {
                        log.info("Consumer thread interrupted");
                        return;
                    }
                    log.info(String.format("Wrote %d characters; values from %d to %d", buf.length, buf[0], buf[buf.length - 1]));
                }
                writer.write(0); // end of stream value
                log.info("Producer finished sending data");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private byte[] getData() {
            byte[] buf = new byte[255 * 4 * 1000];
            byte nextValue = 1;
            for (int i = 0; i < buf.length; ++i) {
                buf[i] = nextValue++;
                // reserve 0 for end of stream
                if (nextValue == 0) {
                    nextValue = 1;
                }
            }
            return buf;
        }
    }

}
