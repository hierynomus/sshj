/*
 * Copyright 2010-2012 sshj contributors
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
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.SocketStreamCopyMonitor;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

public class LocalPortForwarder {

    public static class Parameters {

        private final String localHost;
        private final int localPort;
        private final String remoteHost;
        private final int remotePort;

        public Parameters(String localHost, int localPort, String remoteHost, int remotePort) {
            this.localHost = localHost;
            this.localPort = localPort;
            this.remoteHost = remoteHost;
            this.remotePort = remotePort;
        }

        public String getRemoteHost() {
            return remoteHost;
        }

        public int getRemotePort() {
            return remotePort;
        }

        public String getLocalHost() {
            return localHost;
        }

        public int getLocalPort() {
            return localPort;
        }

    }

    public static class DirectTCPIPChannel
            extends AbstractDirectChannel {

        protected final Socket socket;
        protected final Parameters parameters;

        public DirectTCPIPChannel(Connection conn, Socket socket, Parameters parameters) {
            super(conn, "direct-tcpip");
            this.socket = socket;
            this.parameters = parameters;
        }

        protected void start()
                throws IOException {
            socket.setSendBufferSize(getLocalMaxPacketSize());
            socket.setReceiveBufferSize(getRemoteMaxPacketSize());
            final Event<IOException> soc2chan = new StreamCopier(socket.getInputStream(), getOutputStream())
                    .bufSize(getRemoteMaxPacketSize())
                    .spawnDaemon("soc2chan");
            final Event<IOException> chan2soc = new StreamCopier(getInputStream(), socket.getOutputStream())
                    .bufSize(getLocalMaxPacketSize())
                    .spawnDaemon("chan2soc");
            SocketStreamCopyMonitor.monitor(5, TimeUnit.SECONDS, soc2chan, chan2soc, this, socket);
        }

        @Override
        protected SSHPacket buildOpenReq() {
            return super.buildOpenReq()
                    .putString(parameters.getRemoteHost())
                    .putUInt32(parameters.getRemotePort())
                    .putString(parameters.getLocalHost())
                    .putUInt32(parameters.getLocalPort());
        }

    }

    private final Logger log = LoggerFactory.getLogger(LocalPortForwarder.class);

    private final Connection conn;
    private final Parameters parameters;
    private final ServerSocket serverSocket;

    public LocalPortForwarder(Connection conn, Parameters parameters, ServerSocket serverSocket) {
        this.conn = conn;
        this.parameters = parameters;
        this.serverSocket = serverSocket;
    }

    protected DirectTCPIPChannel openChannel(Socket socket)
            throws TransportException, ConnectionException {
        final DirectTCPIPChannel chan = new DirectTCPIPChannel(conn, socket, parameters);
        chan.open();
        return chan;
    }

    /**
     * Start listening for incoming connections and forward to remote host as a channel.
     *
     * @throws IOException
     */
    public void listen()
            throws IOException {
        log.info("Listening on {}", serverSocket.getLocalSocketAddress());
        while (!Thread.currentThread().isInterrupted()) {
            final Socket socket = serverSocket.accept();
            log.info("Got connection from {}", socket.getRemoteSocketAddress());
            openChannel(socket).start();
        }
        log.info("Interrupted!");
    }

}