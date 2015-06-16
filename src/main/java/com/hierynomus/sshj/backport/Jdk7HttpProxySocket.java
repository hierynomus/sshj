package com.hierynomus.sshj.backport;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.Charset;

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
        getOutputStream().write(httpConnect.getBytes(Charset.forName("UTF-8")));
        checkAndFlushProxyResponse();
    }

    private void checkAndFlushProxyResponse()throws IOException {
        InputStream socketInput = getInputStream();
        byte[] tmpBuffer = new byte[512];
        int len = socketInput.read(tmpBuffer, 0, tmpBuffer.length);

        if (len == 0) {
            throw new SocketException("Empty response from proxy");
        }

        String proxyResponse = new String(tmpBuffer, 0, len, "UTF-8");

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
