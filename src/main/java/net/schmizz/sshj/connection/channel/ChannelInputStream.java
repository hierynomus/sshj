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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;

/**
 * {@link InputStream} for channels. Can {@link #receive(byte[], int, int) receive} data into its buffer for serving to
 * readers.
 */
public final class ChannelInputStream
        extends InputStream
        implements ErrorNotifiable {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final Channel chan;
    private final Transport trans;
    private final Window.Local win;
    private final Buffer.PlainBuffer buf;
    private final byte[] b = new byte[1];

    private boolean eof;
    private SSHException error;

    public ChannelInputStream(Channel chan, Transport trans, Window.Local win) {
        this.chan = chan;
        this.trans = trans;
        this.win = win;
        buf = new Buffer.PlainBuffer(chan.getLocalMaxPacketSize());
    }

    @Override
    public int available() {
        synchronized (buf) {
            return buf.available();
        }
    }

    @Override
    public void close() {
        eof();
    }

    public void eof() {
        synchronized (buf) {
            if (!eof) {
                eof = true;
                buf.notifyAll();
            }
        }
    }

    @Override
    public synchronized void notifyError(SSHException error) {
        this.error = error;
        eof();
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
        synchronized (buf) {
            for (; ; ) {
                if (buf.available() > 0)
                    break;
                if (eof)
                    if (error != null)
                        throw error;
                    else
                        return -1;
                try {
                    buf.wait();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException().initCause(e);
                }
            }
            if (len > buf.available())
                len = buf.available();
            buf.readRawBytes(b, off, len);
            if (buf.rpos() > win.getMaxPacketSize() && buf.available() == 0)
                buf.clear();
        }

        if (!chan.getAutoExpand())
            checkWindow();

        return len;
    }

    public void receive(byte[] data, int offset, int len)
            throws ConnectionException, TransportException {
        if (eof)
            throw new ConnectionException("Getting data on EOF'ed stream");
        synchronized (buf) {
            buf.putRawBytes(data, offset, len);
            buf.notifyAll();
        }
        win.consume(len);
        if (chan.getAutoExpand())
            checkWindow();
    }

    private void checkWindow()
            throws TransportException {
        synchronized (win) {
            final long adjustment = win.neededAdjustment();
            if (adjustment > 0) {
                log.info("Sending SSH_MSG_CHANNEL_WINDOW_ADJUST to #{} for {} bytes", chan.getRecipient(), adjustment);
                trans.write(new SSHPacket(Message.CHANNEL_WINDOW_ADJUST)
                                    .putUInt32(chan.getRecipient()).putUInt32(adjustment));
                win.expand(adjustment);
            }
        }
    }

    @Override
    public String toString() {
        return "< ChannelInputStream for Channel #" + chan.getID() + " >";
    }

}