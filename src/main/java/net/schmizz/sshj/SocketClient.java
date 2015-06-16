/**
 * Copyright 2009 sshj contributors
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

import com.hierynomus.sshj.backport.JavaVersion;
import com.hierynomus.sshj.backport.Jdk7HttpProxySocket;

import javax.net.SocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
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

    SocketClient(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    public void connect(InetAddress host, int port) throws IOException {
        socket = socketFactory.createSocket();
        socket.connect(new InetSocketAddress(host, port), connectTimeout);
        onConnect();
    }


    /**
     * Connect to a host via a proxy.
     * @param host The host address to connect to.
     * @param port The port to connect to.
     * @param proxy The proxy to connect via.
     * @deprecated This method will be removed after v0.12.0. If you want to connect via a proxy, you can do this by injecting a {@link javax.net.SocketFactory}
     *             into the SocketClient. The SocketFactory should create sockets using the {@link java.net.Socket(java.net.Proxy)} constructor.
     */
    @Deprecated
    public void connect(InetAddress host, int port, Proxy proxy) throws IOException {
        if (JavaVersion.isJava7OrEarlier() && proxy.type() == Proxy.Type.HTTP) {
            // Java7 and earlier have no support for HTTP Connect proxies, return our custom socket.
            socket = new Jdk7HttpProxySocket(proxy);
        } else {
            socket = new Socket(proxy);
        }
        socket.connect(new InetSocketAddress(host, port), connectTimeout);
        onConnect();
    }

    public void connect(String hostname, int port) throws IOException {
        this.hostname = hostname;
        connect(InetAddress.getByName(hostname), port);
    }

    /**
     * Connect to a host via a proxy.
     * @param hostname The host name to connect to.
     * @param port The port to connect to.
     * @param proxy The proxy to connect via.
     * @deprecated This method will be removed after v0.12.0. If you want to connect via a proxy, you can do this by injecting a {@link javax.net.SocketFactory}
     *             into the SocketClient. The SocketFactory should create sockets using the {@link java.net.Socket(java.net.Proxy)} constructor.
     */
    @Deprecated
    public void connect(String hostname, int port, Proxy proxy) throws IOException {
        this.hostname = hostname;
        connect(InetAddress.getByName(hostname), port, proxy);
    }

    public void connect(InetAddress host, int port, InetAddress localAddr, int localPort)
            throws IOException {
        socket = socketFactory.createSocket();
        socket.bind(new InetSocketAddress(localAddr, localPort));
        socket.connect(new InetSocketAddress(host, port), connectTimeout);
        onConnect();
    }

    public void connect(String hostname, int port, InetAddress localAddr, int localPort) throws IOException {
        this.hostname = hostname;
        connect(InetAddress.getByName(hostname), port, localAddr, localPort);
    }

    public void connect(InetAddress host) throws IOException {
        connect(host, defaultPort);
    }

    public void connect(String hostname) throws IOException {
        connect(hostname, defaultPort);
    }

    /**
     * Connect to a host via a proxy.
     * @param host The host address to connect to.
     * @param proxy The proxy to connect via.
     * @deprecated This method will be removed after v0.12.0. If you want to connect via a proxy, you can do this by injecting a {@link javax.net.SocketFactory}
     *             into the SocketClient. The SocketFactory should create sockets using the {@link java.net.Socket(java.net.Proxy)} constructor.
     */
    @Deprecated
    public void connect(InetAddress host, Proxy proxy) throws IOException {
        connect(host, defaultPort, proxy);
    }

    /**
     * Connect to a host via a proxy.
     * @param hostname The host name to connect to.
     * @param proxy The proxy to connect via.
     * @deprecated This method will be removed after v0.12.0. If you want to connect via a proxy, you can do this by injecting a {@link javax.net.SocketFactory}
     *             into the SocketClient. The SocketFactory should create sockets using the {@link java.net.Socket(java.net.Proxy)} constructor.
     */
    @Deprecated
    public void connect(String hostname, Proxy proxy) throws IOException {
        connect(hostname, defaultPort, proxy);
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
        return (socket != null) && socket.isConnected();
    }

    public int getLocalPort() {
        return socket.getLocalPort();
    }

    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    public String getRemoteHostname() {
        return hostname == null ? (hostname = getRemoteAddress().getHostName()) : hostname;
    }

    public int getRemotePort() {
        return socket.getPort();
    }

    public InetAddress getRemoteAddress() {
        return socket.getInetAddress();
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
        socket.setSoTimeout(timeout);
        input = socket.getInputStream();
        output = socket.getOutputStream();
    }

}
