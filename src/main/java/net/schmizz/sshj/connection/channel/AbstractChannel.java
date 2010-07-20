/*
 * Copyright 2010 Shikhar Bhushan
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

import net.schmizz.concurrent.Event;
import net.schmizz.concurrent.FutureUtils;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.ByteArrayUtils;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public abstract class AbstractChannel
        implements Channel {

    /** Logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());

    /** Transport layer */
    protected final Transport trans;
    /** Connection layer */
    protected final Connection conn;

    /** Channel type */
    private final String type;
    /** Channel ID */
    private final int id;
    /** Remote recipient ID */
    private int recipient;

    private final Queue<Event<ConnectionException>> chanReqResponseEvents = new LinkedList<Event<ConnectionException>>();

    /* The lock used by to create the open & close events */
    private final ReentrantLock lock = new ReentrantLock();
    /** Channel open event */
    protected final Event<ConnectionException> open;
    /** Channel close event */
    private final Event<ConnectionException> close;

    /* Access to these fields should be synchronized using this object */
    private boolean eofSent;
    private boolean eofGot;
    private boolean closeRequested;

    /** Local window */
    protected final Window.Local lwin;
    /** stdout stream */
    private final ChannelInputStream in;

    /** Remote window */
    protected Window.Remote rwin;
    /** stdin stream */
    private ChannelOutputStream out;

    private volatile boolean autoExpand = false;

    protected AbstractChannel(Connection conn, String type) {
        this.conn = conn;
        this.type = type;
        this.trans = conn.getTransport();

        id = conn.nextID();

        lwin = new Window.Local(conn.getWindowSize(), conn.getMaxPacketSize());
        in = new ChannelInputStream(this, trans, lwin);

        open = new Event<ConnectionException>("chan#" + id + " / " + "open", ConnectionException.chainer, lock);
        close = new Event<ConnectionException>("chan#" + id + " / " + "close", ConnectionException.chainer, lock);
    }

    protected void init(int recipient, int remoteWinSize, int remoteMaxPacketSize) {
        this.recipient = recipient;
        rwin = new Window.Remote(remoteWinSize, remoteMaxPacketSize);
        out = new ChannelOutputStream(this, trans, rwin);
        log.info("Initialized - {}", this);
    }

    @Override
    public boolean getAutoExpand() {
        return autoExpand;
    }

    @Override
    public int getID() {
        return id;
    }

    @Override
    public InputStream getInputStream() {
        return in;
    }

    @Override
    public int getLocalMaxPacketSize() {
        return lwin.getMaxPacketSize();
    }

    @Override
    public int getLocalWinSize() {
        return lwin.getSize();
    }

    @Override
    public OutputStream getOutputStream() {
        return out;
    }

    @Override
    public int getRecipient() {
        return recipient;
    }

    @Override
    public int getRemoteMaxPacketSize() {
        return rwin.getMaxPacketSize();
    }

    @Override
    public int getRemoteWinSize() {
        return rwin.getSize();
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public void handle(Message msg, SSHPacket buf)
            throws ConnectionException, TransportException {
        switch (msg) {

            case CHANNEL_DATA:
                receiveInto(in, buf);
                break;

            case CHANNEL_EXTENDED_DATA:
                gotExtendedData(buf.readInt(), buf);
                break;

            case CHANNEL_WINDOW_ADJUST:
                gotWindowAdjustment(buf.readInt());
                break;

            case CHANNEL_REQUEST:
                gotChannelRequest(buf);
                break;

            case CHANNEL_SUCCESS:
                gotResponse(true);
                break;

            case CHANNEL_FAILURE:
                gotResponse(false);
                break;

            case CHANNEL_EOF:
                gotEOF();
                break;

            case CHANNEL_CLOSE:
                gotClose();
                break;

            default:
                gotUnknown(msg, buf);

        }
    }

    private void gotClose()
            throws TransportException {
        log.info("Got close");
        try {
            closeAllStreams();
            sendClose();
        } finally {
            finishOff();
        }
    }

    /** Called when all I/O streams should be closed. Subclasses can override but must call super. */
    protected void closeAllStreams() {
        IOUtils.closeQuietly(in, out);
    }

    @Override
    public void notifyError(SSHException error) {
        log.debug("Channel #{} got notified of {}", getID(), error.toString());

        FutureUtils.alertAll(error, open, close);
        FutureUtils.alertAll(error, chanReqResponseEvents);

        in.notifyError(error);
        out.notifyError(error);

        finishOff();
    }

    @Override
    public void setAutoExpand(boolean autoExpand) {
        this.autoExpand = autoExpand;
    }

    @Override
    public void close()
            throws ConnectionException, TransportException {
        lock.lock();
        try {
            try {
                sendClose();
            } catch (TransportException e) {
                if (!close.hasError())
                    throw e;
            }
            close.await(conn.getTimeout(), TimeUnit.SECONDS);
        } finally {
            lock.unlock();
        }
    }

    protected synchronized void sendClose()
            throws TransportException {
        try {
            if (!closeRequested) {
                log.info("Sending close");
                trans.write(newBuffer(Message.CHANNEL_CLOSE));
            }
        } finally {
            closeRequested = true;
        }
    }

    @Override
    public synchronized boolean isOpen() {
        lock.lock();
        try {
            return open.isSet() && !close.isSet() && !closeRequested;
        } finally {
            lock.unlock();
        }
    }

    private void gotChannelRequest(SSHPacket buf)
            throws ConnectionException, TransportException {
        final String reqType = buf.readString();
        buf.readBoolean(); // We don't care about the 'want-reply' value
        log.info("Got chan request for `{}`", reqType);
        handleRequest(reqType, buf);
    }

    private void gotWindowAdjustment(int howMuch) {
        log.info("Received window adjustment for {} bytes", howMuch);
        rwin.expand(howMuch);
    }

    /** Called when this channel's end-of-life has been reached. Subclasses may override but must call super. */
    protected void finishOff() {
        conn.forget(this);
        close.set();
    }

    protected void gotExtendedData(int dataTypeCode, SSHPacket buf)
            throws ConnectionException, TransportException {
        throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Extended data not supported on " + type
                                                                       + " channel");
    }

    protected void gotUnknown(Message msg, SSHPacket buf)
            throws ConnectionException, TransportException {
    }

    protected void handleRequest(String reqType, SSHPacket buf)
            throws ConnectionException, TransportException {
        trans.write(newBuffer(Message.CHANNEL_FAILURE));
    }

    protected SSHPacket newBuffer(Message cmd) {
        return new SSHPacket(cmd).putInt(recipient);
    }

    protected void receiveInto(ChannelInputStream stream, SSHPacket buf)
            throws ConnectionException, TransportException {
        final int len = buf.readInt();
        if (len < 0 || len > getLocalMaxPacketSize() || len > buf.available())
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Bad item length: " + len);
        if (log.isTraceEnabled())
            log.trace("IN #{}: {}", id, ByteArrayUtils.printHex(buf.array(), buf.rpos(), len));
        stream.receive(buf.array(), buf.rpos(), len);
    }

    protected synchronized Event<ConnectionException> sendChannelRequest(String reqType, boolean wantReply,
                                                                         Buffer.PlainBuffer reqSpecific)
            throws TransportException {
        log.info("Sending channel request for `{}`", reqType);
        trans.write(
                newBuffer(Message.CHANNEL_REQUEST)
                        .putString(reqType)
                        .putBoolean(wantReply)
                        .putBuffer(reqSpecific)
        );

        Event<ConnectionException> responseEvent = null;
        if (wantReply) {
            responseEvent = new Event<ConnectionException>("chan#" + id + " / " + "chanreq for " + reqType, ConnectionException.chainer, lock);
            chanReqResponseEvents.add(responseEvent);
        }
        return responseEvent;
    }

    private synchronized void gotResponse(boolean success)
            throws ConnectionException {
        final Event<ConnectionException> responseEvent = chanReqResponseEvents.poll();
        if (responseEvent != null) {
            if (success)
                responseEvent.set();
            else
                responseEvent.error(new ConnectionException("Request failed"));
        } else
            throw new ConnectionException(
                    DisconnectReason.PROTOCOL_ERROR,
                    "Received response to channel request when none was requested");
    }

    private synchronized void gotEOF()
            throws TransportException {
        log.info("Got EOF");
        eofGot = true;
        eofInputStreams();
        if (eofSent)
            sendClose();
    }

    /** Called when EOF has been received. Subclasses can override but must call super. */
    protected void eofInputStreams() {
        in.eof();
    }

    @Override
    public synchronized void sendEOF()
            throws TransportException {
        try {
            if (!closeRequested && !eofSent) {
                log.info("Sending EOF");
                trans.write(newBuffer(Message.CHANNEL_EOF));
                if (eofGot)
                    sendClose();
            }
        } finally {
            eofSent = true;
            out.setClosed();
        }
    }

    @Override
    public String toString() {
        return "< " + type + " channel: id=" + id + ", recipient=" + recipient + ", localWin=" + lwin + ", remoteWin="
               + rwin + " >";
    }


}