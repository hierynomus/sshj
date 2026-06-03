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
package com.hierynomus.sshj.userauth.agent;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.SocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;

/**
 * An {@link AgentConnection} over a unix-domain socket, as used by OpenSSH's {@code SSH_AUTH_SOCK}
 * on Linux and macOS.
 * <p>
 * Unix-domain sockets are only in the JDK from Java 16 onwards. sshj's main sources target Java 8,
 * so the Java 16 socket classes are reached reflectively here: this compiles everywhere and works
 * at runtime on a Java 16+ JVM (such as the JetBrains Runtime). On an older runtime the constructor
 * throws an {@link IOException} explaining that you must supply your own {@link AgentConnection}.
 */
public class UnixSocketAgentConnection implements AgentConnection {

    private final SocketChannel channel;
    private final InputStream in;
    private final OutputStream out;

    public UnixSocketAgentConnection(String socketPath) throws IOException {
        this.channel = openUnixSocketChannel(socketPath);
        this.in = Channels.newInputStream(channel);
        this.out = Channels.newOutputStream(channel);
    }

    private static SocketChannel openUnixSocketChannel(String socketPath) throws IOException {
        try {
            // Equivalent to (Java 16+):
            //   SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX);
            //   ch.connect(UnixDomainSocketAddress.of(socketPath));
            Class<?> standardProtocolFamily = Class.forName("java.net.StandardProtocolFamily");
            Object unix = standardProtocolFamily.getField("UNIX").get(null);

            Class<?> unixDomainSocketAddress = Class.forName("java.net.UnixDomainSocketAddress");
            SocketAddress address = (SocketAddress) unixDomainSocketAddress
                    .getMethod("of", String.class).invoke(null, socketPath);

            Method open = SocketChannel.class.getMethod("open", Class.forName("java.net.ProtocolFamily"));
            SocketChannel channel = (SocketChannel) open.invoke(null, unix);
            try {
                channel.connect(address);
            } catch (IOException e) {
                channel.close();
                throw e;
            }
            return channel;
        } catch (ClassNotFoundException | NoSuchMethodException | NoSuchFieldException e) {
            throw new IOException("Unix-domain socket support requires a Java 16+ runtime. "
                    + "On an older runtime, connect to the agent yourself and pass a custom AgentConnection.", e);
        } catch (ReflectiveOperationException e) {
            throw new IOException("Failed to open unix-domain socket to SSH agent at " + socketPath, e);
        }
    }

    @Override
    public InputStream getInputStream() {
        return in;
    }

    @Override
    public OutputStream getOutputStream() {
        return out;
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
