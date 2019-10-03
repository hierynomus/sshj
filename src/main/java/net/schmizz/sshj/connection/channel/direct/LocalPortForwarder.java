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
package net.schmizz.sshj.connection.channel.direct;

import net.schmizz.concurrent.Event;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.channel.SocketStreamCopyMonitor;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.sshj.backport.Sockets.asCloseable;

public class LocalPortForwarder {

    public static class ForwardedChannel
            extends DirectTCPIPChannel {

        protected final Socket socket;

        public ForwardedChannel(Connection conn, Socket socket, Parameters parameters) {
            super(conn, parameters);
            this.socket = socket;
        }

        protected void start()
                throws IOException {
            socket.setSendBufferSize(getLocalMaxPacketSize());
            socket.setReceiveBufferSize(getRemoteMaxPacketSize());
            final Event<IOException> soc2chan = new StreamCopier(socket.getInputStream(), getOutputStream(), loggerFactory)
                    .bufSize(getRemoteMaxPacketSize())
                    .spawnDaemon("soc2chan");
            final Event<IOException> chan2soc = new StreamCopier(getInputStream(), socket.getOutputStream(), loggerFactory)
                    .bufSize(getLocalMaxPacketSize())
                    .spawnDaemon("chan2soc");
            SocketStreamCopyMonitor.monitor(5, TimeUnit.SECONDS, soc2chan, chan2soc, this, socket);
        }
    }

    private final LoggerFactory loggerFactory;
    private final Logger log;
    private final Connection conn;
    private final Parameters parameters;
    private final ServerSocket serverSocket;
    private Thread runningThread;

    public LocalPortForwarder(Connection conn, Parameters parameters, ServerSocket serverSocket, LoggerFactory loggerFactory) {
        this.conn = conn;
        this.parameters = parameters;
        this.serverSocket = serverSocket;
        this.loggerFactory = loggerFactory;
        this.log = loggerFactory.getLogger(getClass());
    }

    private void startChannel(Socket socket) throws IOException {
        ForwardedChannel chan = new ForwardedChannel(conn, socket, parameters);
        try {
            chan.open();
            chan.start();
        } catch (IOException e) {
            IOUtils.closeQuietly(chan, asCloseable(socket));
            throw e;
        }
    }

    /**
     * Start listening for incoming connections and forward to remote host as a channel.
     *
     * @throws IOException
     */
    public void listen() throws IOException {
        listen(Thread.currentThread());
    }

    /**
     * Returns whether this listener is running (ie. whether a thread is attached to it).
     *
     * @return
     */
    public boolean isRunning() {
        return this.runningThread != null && !serverSocket.isClosed();
    }

    /**
     * Start listening for incoming connections and forward to remote host as a channel and ensure that the thread is registered.
     * This is useful if for instance {@link #close() is called from another thread}
     *
     * @throws IOException
     */
    public void listen(Thread runningThread) throws IOException {
        this.runningThread = runningThread;
        log.info("Listening on {}", serverSocket.getLocalSocketAddress());
        while (!runningThread.isInterrupted()) {
            try {
                final Socket socket = serverSocket.accept();
                log.debug("Got connection from {}", socket.getRemoteSocketAddress());
                startChannel(socket);
            } catch (SocketException e) {
                if (!serverSocket.isClosed()) {
                    throw e;
                }
            }
        }
        if (serverSocket.isClosed()) {
            log.debug("LocalPortForwarder closed");
        } else {
            log.debug("LocalPortForwarder interrupted!");
        }
    }

    /**
     * Close the ServerSocket that's listening for connections to forward.
     *
     * @throws IOException
     */
    public void close() throws IOException {
        if (!serverSocket.isClosed()) {
            log.info("Closing listener on {}", serverSocket.getLocalSocketAddress());
            runningThread.interrupt();
            serverSocket.close();
        }
    }

}
