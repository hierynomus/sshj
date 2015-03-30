/**
 * Copyright 2009 sshj contributors
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj;

import javax.net.SocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public abstract class SocketClient {

    private final int defaultPort;

    private Socket socket;
    private InputStream input;
    private OutputStream output;

    private SocketFactory socketFactory = SocketFactory.getDefault();

    private static final int DEFAULT_TIMEOUT = 0;
    private int timeout = DEFAULT_TIMEOUT;

    private String hostname;

    SocketClient(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    public void connect(InetAddress host, int port)
            throws IOException {
        socket = socketFactory.createSocket(host, port);
        onConnect();
    }

    public void connect(String hostname, int port)
            throws IOException {
        this.hostname = hostname;
        connect(InetAddress.getByName(hostname), port);
    }

    public void connect(InetAddress host, int port,
                        InetAddress localAddr, int localPort)
            throws IOException {
        socket = socketFactory.createSocket(host, port, localAddr, localPort);
        onConnect();
    }

    public void connect(String hostname, int port,
                        InetAddress localAddr, int localPort)
            throws IOException {
        this.hostname = hostname;
        connect(InetAddress.getByName(hostname), port, localAddr, localPort);
    }

    public void connect(InetAddress host)
            throws IOException {
        connect(host, defaultPort);
    }

    public void connect(String hostname)
            throws IOException {
        connect(hostname, defaultPort);
    }

    public void disconnect()
            throws IOException {
        if(socket != null) {
            socket.close();
            socket = null;
        }
        if(input != null) {
            input.close();
            input = null;
        }
        if(output != null) {
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
        this.socketFactory = factory;
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

    void onConnect()
            throws IOException {
        socket.setSoTimeout(timeout);
        input = socket.getInputStream();
        output = socket.getOutputStream();
    }

}
