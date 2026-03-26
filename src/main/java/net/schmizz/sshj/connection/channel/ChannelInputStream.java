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
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * {@link InputStream} for channels. Can {@link #receive(byte[], int, int) receive} data into its buffer for serving to
 * readers.
 */
public final class ChannelInputStream
        extends InputStream
        implements ErrorNotifiable {

    private final Logger log;

    private final Channel chan;
    private final Transport trans;
    private final Window.Local win;
    private final int timeoutMs;
    private final CircularBuffer.PlainCircularBuffer buf;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition dataArrived = lock.newCondition();
    private final byte[] b = new byte[1];

    private boolean eof;
    private SSHException error;

    public ChannelInputStream(Channel chan, Transport trans, Window.Local win, int timeoutMs) {
        this.chan = chan;
        this.log = chan.getLoggerFactory().getLogger(getClass());
        this.trans = trans;
        this.win = win;
        this.timeoutMs = timeoutMs;
        this.buf = new CircularBuffer.PlainCircularBuffer(
            chan.getLocalMaxPacketSize(), trans.getConfig().getMaxCircularBufferSize());
    }

    @Override
    public int available() {
        lock.lock();
        try {
            return buf.available();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        eof();
    }

    public void eof() {
        lock.lock();
        try {
            if (!eof) {
                eof = true;
                dataArrived.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void notifyError(SSHException error) {
        lock.lock();
        try {
            this.error = error;
            eof = true;
            dataArrived.signalAll();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int read()
            throws IOException {
        synchronized (b) {
            return read(b, 0, 1) == -1 ? -1 : b[0] & 0xff;
        }
    }

    @Override
    public int read(byte[] b, int off, int len)
            throws IOException {
        lock.lock();
        try {
            while (buf.available() == 0) {
                if (eof) {
                    if (error != null) {
                        throw error;
                    } else {
                        return -1;
                    }
                }
                try {
                    if (timeoutMs > 0) {
                        if (!dataArrived.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                            throw new IOException("Timeout of " + timeoutMs + "ms while waiting for data");
                        }
                    } else {
                        dataArrived.await();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw (IOException) new InterruptedIOException().initCause(e);
                }
            }
            int available = buf.available();
            if (len > available) {
                len = available;
            }
            buf.readRawBytes(b, off, len);

            if (!chan.getAutoExpand()) {
                checkWindow();
            }
        } finally {
            lock.unlock();
        }

        return len;
    }

    public void receive(byte[] data, int offset, int len) throws SSHException {
        if (eof) {
            throw new ConnectionException("Getting data on EOF'ed stream");
        }
        lock.lock();
        try {
            buf.putRawBytes(data, offset, len);
            dataArrived.signalAll();
            // Potential fix for #203 (window consumed below 0).
            // This seems to be a race condition if we receive more data, while we're already sending a SSH_MSG_CHANNEL_WINDOW_ADJUST
            // And the window has not expanded yet.
            win.consume(len);
            if (chan.getAutoExpand()) {
                checkWindow();
            }
        } finally {
            lock.unlock();
        }
    }

    private void checkWindow() throws TransportException {
        /*
         * Window must fit in remaining buffer capacity. We already expect win.size() amount of data to arrive. The
         * difference between that and the remaining capacity is the maximum adjustment we can make to the window.
         */
        final long maxAdjustment = buf.maxPossibleRemainingCapacity() - win.getSize();
        final long adjustment = Math.min(win.neededAdjustment(), maxAdjustment);
        if (adjustment > 0) {
            log.debug("Sending SSH_MSG_CHANNEL_WINDOW_ADJUST to #{} for {} bytes", chan.getRecipient(), adjustment);
            trans.write(new SSHPacket(Message.CHANNEL_WINDOW_ADJUST)
                    .putUInt32FromInt(chan.getRecipient()).putUInt32(adjustment));
            win.expand(adjustment);
        }
    }

    @Override
    public String toString() {
        return "< ChannelInputStream for Channel #" + chan.getID() + " >";
    }

}
