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
package com.hierynomus.sshj.backport;

import net.schmizz.sshj.common.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;

public class Jdk7HttpProxySocket extends Socket {

    private Proxy httpProxy = null;

    public Jdk7HttpProxySocket(Proxy proxy) {
        super(proxy.type() == Proxy.Type.HTTP ? Proxy.NO_PROXY : proxy);
        if (proxy.type() == Proxy.Type.HTTP) {
            this.httpProxy = proxy;
        }
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (httpProxy != null) {
            connectHttpProxy(endpoint, timeout);
        } else {
            super.connect(endpoint, timeout);
        }
    }

    private void connectHttpProxy(SocketAddress endpoint, int timeout) throws IOException {
        super.connect(httpProxy.address(), timeout);

        if (!(endpoint instanceof InetSocketAddress)) {
            throw new SocketException("Expected an InetSocketAddress to connect to, got: " + endpoint);
        }
        InetSocketAddress isa = (InetSocketAddress) endpoint;
        String httpConnect = "CONNECT " + isa.getHostName() + ":" + isa.getPort() + " HTTP/1.0\n\n";
        getOutputStream().write(httpConnect.getBytes(IOUtils.UTF8));
        checkAndFlushProxyResponse();
    }

    private void checkAndFlushProxyResponse()throws IOException {
        InputStream socketInput = getInputStream();
        byte[] tmpBuffer = new byte[512];
        int len = socketInput.read(tmpBuffer, 0, tmpBuffer.length);

        if (len == 0) {
            throw new SocketException("Empty response from proxy");
        }

        String proxyResponse = new String(tmpBuffer, 0, len, IOUtils.UTF8);

        // Expecting HTTP/1.x 200 OK
        if (proxyResponse.contains("200")) {
            // Flush any outstanding message in buffer
            if (socketInput.available() > 0) {
                socketInput.skip(socketInput.available());
            }
            // Proxy Connect Successful
        } else {
            throw new SocketException("Fail to create Socket\nResponse was:" + proxyResponse);
        }
    }
}
