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

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.SSHClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.apache.sshd.server.SshServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.stream.Stream;

import javax.net.SocketFactory;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;


public class ConnectedSocketTest {
    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @BeforeEach
    public void setupClient() throws IOException {
        SSHClient defaultClient = fixture.setupDefaultClient();
    }

    private static interface Connector {
        void connect(SshServerExtension fx) throws IOException;
    }

    private static void connectViaHostname(SshServerExtension fx) throws IOException {
        SshServer server = fx.getServer();
        fx.getClient().connect("localhost", server.getPort());
    }

    private static void connectViaAddr(SshServerExtension fx) throws IOException {
        SshServer server = fx.getServer();
        InetAddress addr = InetAddress.getByName(server.getHost());
        fx.getClient().connect(addr, server.getPort());
    }

    private static Stream<Connector> connectMethods() {
        return Stream.of(fx -> connectViaHostname(fx), fx -> connectViaAddr(fx));
    }

    @ParameterizedTest
    @MethodSource("connectMethods")
    public void connectsIfUnconnected(Connector connector) {
        assertDoesNotThrow(() -> connector.connect(fixture));
    }

    @ParameterizedTest
    @MethodSource("connectMethods")
    public void handlesConnected(Connector connector) throws IOException {
        Socket socket = SocketFactory.getDefault().createSocket();
        SocketFactory factory = new SocketFactory() {
                @Override
                public Socket createSocket() {
                    return socket;
                }
                @Override
                public Socket createSocket(InetAddress host, int port) {
                    return socket;
                }
                @Override
                public Socket createSocket(InetAddress address, int port,
                                           InetAddress localAddress, int localPort) {
                    return socket;
                }
                @Override
                public Socket createSocket(String host, int port) {
                    return socket;
                }
                @Override
                public Socket createSocket(String host, int port,
                                           InetAddress localHost, int localPort) {
                    return socket;
                }
            };
        socket.connect(new InetSocketAddress("localhost", fixture.getServer().getPort()));
        fixture.getClient().setSocketFactory(factory);
        assertDoesNotThrow(() -> connector.connect(fixture));
    }
}
