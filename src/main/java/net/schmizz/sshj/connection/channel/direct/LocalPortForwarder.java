/*
 * Copyright 2010 Shikhar Bhushan
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

import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.common.StreamCopier.ErrorCallback;
import net.schmizz.sshj.connection.Connection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ServerSocketFactory;
import java.io.Closeable;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;

public class LocalPortForwarder {

    private class DirectTCPIPChannel
            extends AbstractDirectChannel {

        private final Socket sock;

        private DirectTCPIPChannel(Connection conn, Socket sock) {
            super(conn, "direct-tcpip");
            this.sock = sock;
        }

        private void start()
                throws IOException {
            sock.setSendBufferSize(getLocalMaxPacketSize());
            sock.setReceiveBufferSize(getRemoteMaxPacketSize());

            final ErrorCallback closer = StreamCopier.closeOnErrorCallback(this,
                                                                           new Closeable() {
                                                                               @Override
                                                                               public void close()
                                                                                       throws IOException {
                                                                                   sock.close();
                                                                               }
                                                                           });

            new StreamCopier("chan2soc", getInputStream(), sock.getOutputStream())
                    .bufSize(getLocalMaxPacketSize())
                    .errorCallback(closer)
                    .daemon(true)
                    .start();

            new StreamCopier("soc2chan", sock.getInputStream(), getOutputStream())
                    .bufSize(getRemoteMaxPacketSize())
                    .errorCallback(closer)
                    .daemon(true)
                    .start();
        }

        @Override
        protected SSHPacket buildOpenReq() {
            return super.buildOpenReq()
                    .putString(host)
                    .putInt(port)
                    .putString(ss.getInetAddress().getHostAddress())
                    .putInt(ss.getLocalPort());
        }

    }

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final Connection conn;
    private final ServerSocket ss;
    private final String host;
    private final int port;

    /**
     * Create a local port forwarder with specified binding ({@code listeningAddr}. It does not, however, start
     * listening unless {@link #listen() explicitly told to}. The {@link javax.net.ServerSocketFactory#getDefault()
     * default} server socket factory is used.
     *
     * @param conn          {@link Connection} implementation
     * @param listeningAddr {@link SocketAddress} this forwarder will listen on, if {@code null} then an ephemeral port
     *                      and valid local address will be picked to bind the server socket
     * @param host          what host the SSH server will further forward to
     * @param port          port on {@code toHost}
     *
     * @throws IOException if there is an error binding on specified {@code listeningAddr}
     */
    public LocalPortForwarder(Connection conn, SocketAddress listeningAddr, String host, int port)
            throws IOException {
        this(ServerSocketFactory.getDefault(), conn, listeningAddr, host, port);
    }

    /**
     * Create a local port forwarder with specified binding ({@code listeningAddr}. It does not, however, start
     * listening unless {@link #listen() explicitly told to}.
     *
     * @param ssf           factory to use for creating the server socket
     * @param conn          {@link Connection} implementation
     * @param listeningAddr {@link SocketAddress} this forwarder will listen on, if {@code null} then an ephemeral port
     *                      and valid local address will be picked to bind the server socket
     * @param host          what host the SSH server will further forward to
     * @param port          port on {@code toHost}
     *
     * @throws IOException if there is an error binding on specified {@code listeningAddr}
     */
    public LocalPortForwarder(ServerSocketFactory ssf, Connection conn, SocketAddress listeningAddr, String host, int port)
            throws IOException {
        this.conn = conn;
        this.host = host;
        this.port = port;
        this.ss = ssf.createServerSocket();
        ss.setReceiveBufferSize(conn.getMaxPacketSize());
        ss.bind(listeningAddr);
    }

    /** @return the address to which this forwarder is bound for listening */
    public SocketAddress getListeningAddress() {
        return ss.getLocalSocketAddress();
    }

    /**
     * Start listening for incoming connections and forward to remote host as a channel.
     *
     * @throws IOException
     */
    public void listen()
            throws IOException {
        log.info("Listening on {}", ss.getLocalSocketAddress());
        Socket sock;
        while (!Thread.currentThread().isInterrupted()) {
            sock = ss.accept();
            log.info("Got connection from {}", sock.getRemoteSocketAddress());
            DirectTCPIPChannel chan = new DirectTCPIPChannel(conn, sock);
            chan.open();
            chan.start();
        }
    }

}