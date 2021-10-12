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
package net.schmizz.sshj.connection.channel;

import net.schmizz.sshj.common.*;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;

import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * {@link OutputStream} for channels. Buffers data upto the remote window's maximum packet size. Data can also be
 * flushed via {@link #flush()} and is also flushed on {@link #close()}.
 */
public final class ChannelOutputStream extends OutputStream implements ErrorNotifiable {

    private final Channel chan;
    private final Transport trans;
    private final Window.Remote win;

    private final DataBuffer buffer = new DataBuffer();
    private final byte[] b = new byte[1];

    private AtomicBoolean closed;
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

        int write(byte[] data, int off, int len) throws TransportException, ConnectionException {
            final int bufferSize = packet.wpos() - dataOffset;
            if (bufferSize >= win.getMaxPacketSize()) {
                flush(bufferSize, true);
                return 0;
            } else {
                final int n = Math.min(len, win.getMaxPacketSize() - bufferSize);
                packet.putRawBytes(data, off, n);
                return n;
            }
        }

        boolean flush(boolean canAwaitExpansion) throws TransportException, ConnectionException {
            return flush(packet.wpos() - dataOffset, canAwaitExpansion);
        }

        boolean flush(int bufferSize, boolean canAwaitExpansion) throws TransportException, ConnectionException {
            int dataLeft = bufferSize;
            while (dataLeft > 0) {
                long remoteWindowSize = win.getSize();
                if (remoteWindowSize == 0) {
                    if (canAwaitExpansion) {
                        remoteWindowSize = win.awaitExpansion(remoteWindowSize);
                    } else {
                        return false;
                    }
                }

                // We can only write the min. of
                // a) how much data we have
                // b) the max packet size
                // c) what the current window size will allow
                final int writeNow = Math.min(dataLeft, (int) Math.min(win.getMaxPacketSize(), remoteWindowSize));

                packet.wpos(headerOffset);
                packet.putMessageID(Message.CHANNEL_DATA);
                packet.putUInt32FromInt(chan.getRecipient());
                packet.putUInt32(writeNow);
                packet.wpos(dataOffset + writeNow);

                final int leftOverBytes = dataLeft - writeNow;
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

                dataLeft = leftOverBytes;
            }

            return true;
        }

    }

    public ChannelOutputStream(Channel chan, Transport trans, Window.Remote win) {
        this.chan = chan;
        this.trans = trans;
        this.win = win;
        this.closed = new AtomicBoolean(false);
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
        int length = len;
        int offset = off;
        while (length > 0) {
            final int n = buffer.write(data, offset, length);
            offset += n;
            length -= n;
        }
    }

    @Override
    public synchronized void notifyError(SSHException error) {
        this.error = error;
    }

    private void checkClose() throws SSHException {
        // Check whether either the Stream is closed, or the underlying channel is closed
        if (closed.get() || !chan.isOpen()) {
            if (error != null) {
                throw error;
            } else {
                throw new ConnectionException("Stream closed");
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        // Not closed yet, and underlying channel is open to flush the data to.
        if (!closed.getAndSet(true) && chan.isOpen()) {
            buffer.flush(false);
            trans.write(new SSHPacket(Message.CHANNEL_EOF).putUInt32(chan.getRecipient()));
        }
    }

    /**
     * Send all data currently buffered. If window space is exhausted in the process, this will block
     * until it is expanded by the server.
     *
     * @throws IOException
     */
    @Override
    public synchronized void flush() throws IOException {
        checkClose();
        buffer.flush(true);
    }

    @Override
    public String toString() {
        return "< ChannelOutputStream for Channel #" + chan.getID() + " >";
    }

}
