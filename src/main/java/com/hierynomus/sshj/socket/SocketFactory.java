package com.hierynomus.sshj.socket;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;

import static java.lang.String.format;

/**
 * https://code.google.com/p/java-socket-over-http-proxy-connect/source/browse/trunk/src/sg/com/en/SocketFactory.java
 */
public class SocketFactory {

    private static final int DEFAULT_CONNECT_TIMEOUT = 0;
    private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;

    private final javax.net.SocketFactory delegateSocketFactory = javax.net.SocketFactory.getDefault();

    public static SocketFactory getDefault() {
        return new SocketFactory();
    }

    public Socket createSocket(String address, int port) throws IOException {
        return createSocket(new InetSocketAddress(address, port));
    }

    public Socket createSocket(InetSocketAddress inetSocketAddress) throws IOException {
        Socket socket = delegateSocketFactory.createSocket();
        socket.connect(inetSocketAddress, connectTimeout);
        return socket;
    }

    public Socket createSocket(InetSocketAddress inetSocketAddress, Proxy proxy) throws IOException {
        if (proxy.type() == Proxy.Type.HTTP) {
            return createHttpProxySocket(inetSocketAddress, proxy);
        }
        Socket socket = new Socket(proxy);
        socket.connect(inetSocketAddress, connectTimeout);
        return socket;
    }

    private Socket createHttpProxySocket(InetSocketAddress inetSocketAddress, Proxy proxy) throws IOException {
        Socket socket = delegateSocketFactory.createSocket();
        socket.connect(proxy.address());

        String connect = format("CONNECT %s:%d\n\n", inetSocketAddress.getHostName(), inetSocketAddress.getPort());
        socket.getOutputStream().write(connect.getBytes());
        checkAndFlushProxyResponse(socket);
        return socket;
    }

    private void checkAndFlushProxyResponse(Socket socket)throws IOException {
        InputStream socketInput = socket.getInputStream();
        byte[] tmpBuffer = new byte[512];
        int len = socketInput.read(tmpBuffer, 0, tmpBuffer.length);

        if (len == 0) {
            throw new SocketException("Empty response from proxy");
        }

        String proxyResponse = new String(tmpBuffer, 0, len, "UTF-8");

        // Expecting HTTP/1.x 200 OK
        if (proxyResponse.contains("200")) {
            // Flush any outstanding message in buffer
            if (socketInput.available() > 0)
                socketInput.skip(socketInput.available());
            // Proxy Connect Successful
        } else {
            throw new SocketException("Fail to create Socket\nResponse was:" + proxyResponse);
        }
    }

    public Socket createSocket(InetSocketAddress bindpoint, InetSocketAddress endpoint) throws IOException {
        Socket socket = delegateSocketFactory.createSocket();
        socket.bind(bindpoint);
        socket.connect(endpoint, connectTimeout);
        return socket;
    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

}
