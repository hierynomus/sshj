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
package net.schmizz.sshj.connection.channel.forwarded;

import net.schmizz.concurrent.Event;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.connection.channel.SocketStreamCopyMonitor;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.concurrent.TimeUnit;

/** A {@link ConnectListener} that forwards what is received over the channel to a socket and vice-versa. */
public class SocketForwardingConnectListener
        implements ConnectListener {

    protected final SocketAddress addr;

    /** Create with a {@link SocketAddress} this listener will forward to. */
    public SocketForwardingConnectListener(SocketAddress addr) {
        this.addr = addr;
    }

    /** On connect, confirm the channel and start forwarding. */
    @Override
    public void gotConnect(Channel.Forwarded chan)
            throws IOException {
        chan.getLoggerFactory().getLogger(getClass()).debug("New connection from {}:{}", chan.getOriginatorIP(), chan.getOriginatorPort());

        final Socket sock = new Socket();
        sock.setSendBufferSize(chan.getLocalMaxPacketSize());
        sock.setReceiveBufferSize(chan.getRemoteMaxPacketSize());

        sock.connect(addr);

        // ok so far -- could connect, let's confirm the channel
        chan.confirm();

        final Event<IOException> soc2chan = new StreamCopier(sock.getInputStream(), chan.getOutputStream(), chan.getLoggerFactory())
                .bufSize(chan.getRemoteMaxPacketSize())
                .spawnDaemon("soc2chan");

        final Event<IOException> chan2soc = new StreamCopier(chan.getInputStream(), sock.getOutputStream(), chan.getLoggerFactory())
                .bufSize(chan.getLocalMaxPacketSize())
                .spawnDaemon("chan2soc");

        SocketStreamCopyMonitor.monitor(5, TimeUnit.SECONDS, chan2soc, soc2chan, chan, sock);
    }

}
