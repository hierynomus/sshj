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
package net.schmizz.sshj;

import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.connection.channel.direct.DirectConnection;

import javax.net.SocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

public abstract class SocketClient {

    private final int defaultPort;

    private Socket socket;
    private InputStream input;
    private OutputStream output;

    private SocketFactory socketFactory = SocketFactory.getDefault();

    private static final int DEFAULT_CONNECT_TIMEOUT = 0;
    private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;

    private int timeout = 0;

    private String hostname;
    private int port;

    private boolean tunneled = false;

    SocketClient(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    protected InetSocketAddress makeInetSocketAddress(String hostname, int port) {
        return new InetSocketAddress(hostname, port);
    }

    public void connect(String hostname) throws IOException {
        connect(hostname, defaultPort);
    }

    public void connect(String hostname, int port) throws IOException {
        if (hostname == null) {
            connect(InetAddress.getByName(null), port);
        } else {
            this.hostname = hostname;
            this.port = port;
            socket = socketFactory.createSocket();
            if (! socket.isConnected()) {
                socket.connect(makeInetSocketAddress(hostname, port), connectTimeout);
            }
            onConnect();
        }
    }

    public void connect(String hostname, int port, InetAddress localAddr, int localPort) throws IOException {
        if (hostname == null) {
            connect(InetAddress.getByName(null), port, localAddr, localPort);
        } else {
            this.hostname = hostname;
            this.port = port;
            socket = socketFactory.createSocket();
            socket.bind(new InetSocketAddress(localAddr, localPort));
            socket.connect(makeInetSocketAddress(hostname, port), connectTimeout);
            onConnect();
        }
    }

    public void connectVia(Channel channel, String hostname, int port) throws IOException {
        this.hostname = hostname;
        this.port = port;
        this.input = channel.getInputStream();
        this.output = channel.getOutputStream();
        this.tunneled = true;
        onConnect();
    }

    /** Connect to a remote address via a direct TCP/IP connection from the server. */
    public void connectVia(DirectConnection directConnection) throws IOException {
        connectVia(directConnection, directConnection.getRemoteHost(), directConnection.getRemotePort());
    }

    public void connect(InetAddress host) throws IOException {
        connect(host, defaultPort);
    }

    public void connect(InetAddress host, int port) throws IOException {
        this.port = port;
        socket = socketFactory.createSocket();
        if (! socket.isConnected()) {
            socket.connect(new InetSocketAddress(host, port), connectTimeout);
        }
        onConnect();
    }

    public void connect(InetAddress host, int port, InetAddress localAddr, int localPort)
            throws IOException {
        this.port = port;
        socket = socketFactory.createSocket();
        socket.bind(new InetSocketAddress(localAddr, localPort));
        socket.connect(new InetSocketAddress(host, port), connectTimeout);
        onConnect();
    }

    public void disconnect() throws IOException {
        if (socket != null) {
            socket.close();
            socket = null;
        }
        if (input != null) {
            input.close();
            input = null;
        }
        if (output != null) {
            output.close();
            output = null;
        }
    }

    public boolean isConnected() {
        return tunneled || ((socket != null) && socket.isConnected());
    }

    public int getLocalPort() {
        return tunneled ? 65536 : socket.getLocalPort();
    }

    public InetAddress getLocalAddress() {
        return socket == null ? null : socket.getLocalAddress();
    }

    public String getRemoteHostname() {
        return hostname == null ? (hostname = getRemoteAddress().getHostName()) : hostname;
    }

    public int getRemotePort() {
        return socket == null ? this.port : socket.getPort();
    }

    public InetAddress getRemoteAddress() {
        return socket == null ? null : socket.getInetAddress();
    }

    public void setSocketFactory(SocketFactory factory) {
        if (factory == null) {
            socketFactory = SocketFactory.getDefault();
        } else {
            socketFactory = factory;
        }
    }

    public SocketFactory getSocketFactory() {
        return socketFactory;
    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public Socket getSocket() {
        return socket;
    }

    InputStream getInputStream() {
        return input;
    }

    OutputStream getOutputStream() {
        return output;
    }

    void onConnect() throws IOException {
        if (socket != null) {
            socket.setSoTimeout(timeout);
            input = socket.getInputStream();
            output = socket.getOutputStream();
        }
    }

}
