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

import net.schmizz.concurrent.ErrorDeliveryUtil;
import net.schmizz.concurrent.Event;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public abstract class AbstractChannel
        implements Channel {

    private static final int REMOTE_MAX_PACKET_SIZE_CEILING = 1024 * 1024;

    /** Logger */
    protected final LoggerFactory loggerFactory;
    protected final Logger log;

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
    /** Remote character set */
    private final Charset remoteCharset;

    private boolean eof = false;

    private final Queue<Event<ConnectionException>> chanReqResponseEvents = new LinkedList<Event<ConnectionException>>();

    /* The lock used by to create the open & close events */
    private final ReentrantLock openCloseLock = new ReentrantLock();
    /** Channel open event */
    protected final Event<ConnectionException> openEvent;
    /** Channel close event */
    protected final Event<ConnectionException> closeEvent;
    /** Whether we have already sent a CHANNEL_CLOSE request to the server */
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
        this(conn, type, null);
    }
    protected AbstractChannel(Connection conn, String type, Charset remoteCharset) {
        this.conn = conn;
        this.loggerFactory = conn.getTransport().getConfig().getLoggerFactory();
        this.type = type;
        this.log = loggerFactory.getLogger(getClass());
        this.trans = conn.getTransport();

        this.remoteCharset = remoteCharset != null ? remoteCharset : IOUtils.UTF8;
        id = conn.nextID();

        lwin = new Window.Local(conn.getWindowSize(), conn.getMaxPacketSize(), loggerFactory);
        in = new ChannelInputStream(this, trans, lwin);

        openEvent = new Event<ConnectionException>("chan#" + id + " / " + "open", ConnectionException.chainer, openCloseLock, loggerFactory);
        closeEvent = new Event<ConnectionException>("chan#" + id + " / " + "close", ConnectionException.chainer, openCloseLock, loggerFactory);
    }

    protected void init(int recipient, long remoteWinSize, long remoteMaxPacketSize) {
        this.recipient = recipient;
        rwin = new Window.Remote(remoteWinSize, (int) Math.min(remoteMaxPacketSize, REMOTE_MAX_PACKET_SIZE_CEILING),
            conn.getTimeoutMs(), loggerFactory);
        out = new ChannelOutputStream(this, trans, rwin);
        log.debug("Initialized - {}", this);
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
    public long getLocalWinSize() {
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
    public Charset getRemoteCharset() {
        return remoteCharset;
    }

    @Override
    public int getRemoteMaxPacketSize() {
        return rwin.getMaxPacketSize();
    }

    @Override
    public long getRemoteWinSize() {
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
                gotExtendedData(buf);
                break;

            case CHANNEL_WINDOW_ADJUST:
                gotWindowAdjustment(buf);
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
                break;
        }
    }

    @Override
    public boolean isEOF() {
        return eof;
    }

    @Override
    public LoggerFactory getLoggerFactory() {
        return loggerFactory;
    }

    private void gotClose()
            throws TransportException {
        log.debug("Got close");
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

        ErrorDeliveryUtil.alertEvents(error, openEvent, closeEvent);
        ErrorDeliveryUtil.alertEvents(error, chanReqResponseEvents);

        in.notifyError(error);
        if (out != null)
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
        openCloseLock.lock();
        try {
            if (isOpen()) {
                try {
                    sendClose();
                } catch (TransportException e) {
                    if (!closeEvent.inError())
                        throw e;
                }
                closeEvent.await(conn.getTimeoutMs(), TimeUnit.MILLISECONDS);
            }
        } finally {
            openCloseLock.unlock();
        }
    }

    public void join()
            throws ConnectionException {
        closeEvent.await();
    }

    public void join(long timeout, TimeUnit unit)
            throws ConnectionException {
        closeEvent.await(timeout, unit);
    }

    protected void sendClose()
            throws TransportException {
        openCloseLock.lock();
        try {
            if (!closeRequested) {
                log.debug("Sending close");
                trans.write(newBuffer(Message.CHANNEL_CLOSE));
            }
        } finally {
            closeRequested = true;
            openCloseLock.unlock();
        }
    }

    @Override
    public boolean isOpen() {
        openCloseLock.lock();
        try {
            return openEvent.isSet() && !closeEvent.isSet() && !closeRequested;
        } finally {
            openCloseLock.unlock();
        }
    }

    private void gotChannelRequest(SSHPacket buf)
            throws ConnectionException, TransportException {
        final String reqType;
        try {
            reqType = buf.readString();
            buf.readBoolean(); // We don't care about the 'want-reply' value
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
        log.debug("Got chan request for `{}`", reqType);
        handleRequest(reqType, buf);
    }

    private void gotWindowAdjustment(SSHPacket buf)
            throws ConnectionException {
        final long howMuch;
        try {
            howMuch = buf.readUInt32();
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
        log.debug("Received window adjustment for {} bytes", howMuch);
        rwin.expand(howMuch);
    }

    protected void finishOff() {
        conn.forget(this);
        closeEvent.set();
    }

    protected void gotExtendedData(SSHPacket buf)
            throws ConnectionException, TransportException {
        throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                      "Extended data not supported on " + type + " channel");
    }

    protected void gotUnknown(Message msg, SSHPacket buf)
            throws ConnectionException, TransportException {
        log.warn("Got unknown packet with type {}", msg);

    }

    protected void handleRequest(String reqType, SSHPacket buf)
            throws ConnectionException, TransportException {
        trans.write(newBuffer(Message.CHANNEL_FAILURE));
    }

    protected SSHPacket newBuffer(Message cmd) {
        return new SSHPacket(cmd).putUInt32(recipient);
    }

    protected void receiveInto(ChannelInputStream stream, SSHPacket buf)
            throws ConnectionException, TransportException {
        final int len;
        try {
            len = buf.readUInt32AsInt();
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
        if (len < 0 || len > getLocalMaxPacketSize() || len > buf.available()) {
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR, "Bad item length: " + len);
        }
        if (log.isTraceEnabled()) {
            log.trace("IN #{}: {}", id, ByteArrayUtils.printHex(buf.array(), buf.rpos(), len));
        }
        stream.receive(buf.array(), buf.rpos(), len);
    }

    protected Event<ConnectionException> sendChannelRequest(String reqType, boolean wantReply,
                                                            Buffer.PlainBuffer reqSpecific)
            throws TransportException {
        log.debug("Sending channel request for `{}`", reqType);
        synchronized (chanReqResponseEvents) {
            trans.write(
                    newBuffer(Message.CHANNEL_REQUEST)
                            .putString(reqType)
                            .putBoolean(wantReply)
                            .putBuffer(reqSpecific)
            );

            Event<ConnectionException> responseEvent = null;
            if (wantReply) {
                responseEvent = new Event<ConnectionException>("chan#" + id + " / " + "chanreq for " + reqType,
                                                               ConnectionException.chainer, loggerFactory);
                chanReqResponseEvents.add(responseEvent);
            }
            return responseEvent;
        }
    }

    private void gotResponse(boolean success)
            throws ConnectionException {
        synchronized (chanReqResponseEvents) {
            final Event<ConnectionException> responseEvent = chanReqResponseEvents.poll();
            if (responseEvent != null) {
                if (success)
                    responseEvent.set();
                else
                    responseEvent.deliverError(new ConnectionException("Request failed"));
            } else
                throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                              "Received response to channel request when none was requested");
        }
    }

    private void gotEOF()
            throws TransportException {
        log.debug("Got EOF");
        eofInputStreams();
    }

    /** Called when EOF has been received. Subclasses can override but must call super. */
    protected void eofInputStreams() {
        in.eof();
        eof = true;
    }

    @Override
    public String toString() {
        return "< " + type + " channel: id=" + id + ", recipient=" + recipient + ", localWin=" + lwin + ", remoteWin="
                + rwin + " >";
    }


}
