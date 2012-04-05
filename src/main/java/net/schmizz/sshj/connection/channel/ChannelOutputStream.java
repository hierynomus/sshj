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
 * This file may incorporate work covered by the following copyright and
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
package net.schmizz.sshj.connection.channel;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.ErrorNotifiable;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;

import java.io.IOException;
import java.io.OutputStream;

/**
 * {@link OutputStream} for channels. Buffers data upto the remote window's maximum packet size. Data can also be
 * flushed via {@link #flush()} and is also flushed on {@link #close()}.
 */
public final class ChannelOutputStream
        extends OutputStream
        implements ErrorNotifiable {

    private final Channel chan;
    private final Transport trans;
    private final Window.Remote win;

    private final DataBuffer buffer = new DataBuffer();
    private final byte[] b = new byte[1];

    private boolean closed;
    private SSHException error;

    private final class DataBuffer {

        private final int headerOffset;
        private final int dataOffset;

        private final SSHPacket packet = new SSHPacket(Message.CHANNEL_DATA);
        private final Buffer.PlainBuffer leftOvers = new Buffer.PlainBuffer();

        DataBuffer() {
            headerOffset = packet.rpos();
            packet.putUInt32(0); // recipient
            packet.putUInt32(0); // data length
            dataOffset = packet.wpos();
        }

        int write(byte[] data, int off, int len)
                throws TransportException, ConnectionException {
            final int bufferSize = packet.wpos() - dataOffset;
            if (bufferSize >= win.getMaxPacketSize()) {
                flush(bufferSize);
                return 0;
            } else {
                final int n = Math.min(len - off, win.getMaxPacketSize() - bufferSize);
                packet.putRawBytes(data, off, n);
                return n;
            }
        }

        void flush()
                throws TransportException, ConnectionException {
            flush(packet.wpos() - dataOffset);
        }
        
        void flush(int bufferSize)
                throws TransportException, ConnectionException {
            while (bufferSize > 0) {

                long remoteWindowSize = win.getSize();
                if (remoteWindowSize == 0)
                    remoteWindowSize = win.awaitExpansion(remoteWindowSize);

                // We can only write the min. of
                // a) how much data we have
                // b) the max packet size
                // c) what the current window size will allow
                final int writeNow = Math.min(bufferSize, (int) Math.min(win.getMaxPacketSize(), remoteWindowSize));

                packet.wpos(headerOffset);
                packet.putMessageID(Message.CHANNEL_DATA);
                packet.putUInt32(chan.getRecipient());
                packet.putUInt32(writeNow);
                packet.wpos(dataOffset + writeNow);

                final int leftOverBytes = bufferSize - writeNow;
                if (leftOverBytes > 0) {
                    leftOvers.putRawBytes(packet.array(), packet.wpos(), leftOverBytes);
                }

                trans.write(packet);
                win.consume(writeNow);

                packet.rpos(headerOffset);
                packet.wpos(dataOffset);

                if (leftOverBytes > 0) {
                    packet.putBuffer(leftOvers);
                    leftOvers.clear();
                }

                bufferSize = leftOverBytes;
            }
        }

    }

    public ChannelOutputStream(Channel chan, Transport trans, Window.Remote win) {
        this.chan = chan;
        this.trans = trans;
        this.win = win;
    }

    @Override
    public synchronized void write(int w)
            throws IOException {
        b[0] = (byte) w;
        write(b, 0, 1);
    }

    @Override
    public synchronized void write(final byte[] data, int off, int len)
            throws IOException {
        checkClose();
        while (len > 0) {
            final int n = buffer.write(data, off, len);
            off += n;
            len -= n;
        }
    }

    @Override
    public synchronized void notifyError(SSHException error) {
        this.error = error;
    }

    private void checkClose()
            throws SSHException {
        if (closed) {
            if (error != null)
                throw error;
            else
                throw new ConnectionException("Stream closed");
        }
    }

    @Override
    public synchronized void close()
            throws IOException {
        if (!closed) {
            try {
                buffer.flush();
                chan.sendEOF();
            } finally {
                setClosed();
            }
        }
    }

    public synchronized void setClosed() {
        closed = true;
    }

    /**
     * Send all data currently buffered. If window space is exhausted in the process, this will block
     * until it is expanded by the server.
     *
     * @throws IOException
     */
    @Override
    public synchronized void flush()
            throws IOException {
        checkClose();
        buffer.flush();
    }

    @Override
    public String toString() {
        return "< ChannelOutputStream for Channel #" + chan.getID() + " >";
    }

}