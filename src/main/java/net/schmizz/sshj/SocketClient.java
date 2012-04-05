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
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */
package net.schmizz.sshj;

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

    SocketClient(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    public void connect(InetAddress host, int port)
            throws IOException {
        socket = socketFactory.createSocket();
        socket.connect(new InetSocketAddress(host, port), connectTimeout);
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
        socket = socketFactory.createSocket();
        socket.bind(new InetSocketAddress(localAddr, localPort));
        socket.connect(new InetSocketAddress(host, port), connectTimeout);
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
        if (factory == null)
            socketFactory = SocketFactory.getDefault();
        else
            socketFactory = factory;
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

    void onConnect()
            throws IOException {
        socket.setSoTimeout(timeout);
        input = socket.getInputStream();
        output = socket.getOutputStream();
    }

}