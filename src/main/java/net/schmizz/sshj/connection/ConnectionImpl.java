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
 */
package net.schmizz.sshj.connection;

import net.schmizz.concurrent.ErrorDeliveryUtil;
import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.AbstractService;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.ErrorNotifiable;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.connection.channel.OpenFailException.Reason;
import net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;

import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** {@link Connection} implementation. */
public class ConnectionImpl
        extends AbstractService
        implements Connection {

    private final Object internalSynchronizer = new Object();

    private final AtomicInteger nextID = new AtomicInteger();

    private final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();

    private final Map<String, ForwardedChannelOpener> openers = new ConcurrentHashMap<String, ForwardedChannelOpener>();

    private final Queue<Promise<SSHPacket, ConnectionException>> globalReqPromises = new LinkedList<Promise<SSHPacket, ConnectionException>>();

    private long windowSize = 2048 * 1024;
    private int maxPacketSize = 32 * 1024;

    /**
     * Create with an associated {@link Transport}.
     *
     * @param trans transport layer
     */
    public ConnectionImpl(Transport trans) {
        super("ssh-connection", trans);
    }

    @Override
    public void attach(Channel chan) {
        log.info("Attaching `{}` channel (#{})", chan.getType(), chan.getID());
        channels.put(chan.getID(), chan);
    }

    @Override
    public Channel get(int id) {
        return channels.get(id);
    }

    @Override
    public ForwardedChannelOpener get(String chanType) {
        return openers.get(chanType);
    }

    @Override
    public void forget(Channel chan) {
        log.info("Forgetting `{}` channel (#{})", chan.getType(), chan.getID());
        channels.remove(chan.getID());
        synchronized (internalSynchronizer) {
            if (channels.isEmpty())
                internalSynchronizer.notifyAll();
        }
    }

    @Override
    public void forget(ForwardedChannelOpener opener) {
        log.info("Forgetting opener for `{}` channels: {}", opener.getChannelType(), opener);
        openers.remove(opener.getChannelType());
    }

    @Override
    public void attach(ForwardedChannelOpener opener) {
        log.info("Attaching opener for `{}` channels: {}", opener.getChannelType(), opener);
        openers.put(opener.getChannelType(), opener);
    }

    private Channel getChannel(SSHPacket buffer)
            throws ConnectionException {
        try {
            final int recipient = buffer.readUInt32AsInt();
            final Channel channel = get(recipient);
            if (channel != null)
                return channel;
            else {
                buffer.rpos(buffer.rpos() - 5);
                throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                              "Received " + buffer.readMessageID() + " on unknown channel #" + recipient);
            }
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
    }

    @Override
    public void handle(Message msg, SSHPacket buf)
            throws SSHException {
        if (msg.in(91, 100))
            getChannel(buf).handle(msg, buf);

        else if (msg.in(80, 90))
            switch (msg) {
                case REQUEST_SUCCESS:
                    gotGlobalReqResponse(buf);
                    break;
                case REQUEST_FAILURE:
                    gotGlobalReqResponse(null);
                    break;
                case CHANNEL_OPEN:
                    gotChannelOpen(buf);
                    break;
                default:
                    super.handle(msg, buf);
            }

        else
            super.handle(msg, buf);
    }

    @Override
    public int getMaxPacketSize() {
        return maxPacketSize;
    }

    @Override
    public Transport getTransport() {
        return trans;
    }

    @Override
    public void setMaxPacketSize(int maxPacketSize) {
        this.maxPacketSize = maxPacketSize;
    }

    @Override
    public long getWindowSize() {
        return windowSize;
    }

    @Override
    public void setWindowSize(long windowSize) {
        this.windowSize = windowSize;
    }

    @Override
    public void join()
            throws InterruptedException {
        synchronized (internalSynchronizer) {
            while (!channels.isEmpty())
                internalSynchronizer.wait();
        }
    }

    @Override
    public int nextID() {
        return nextID.getAndIncrement();
    }

    @Override
    public Promise<SSHPacket, ConnectionException> sendGlobalRequest(String name, boolean wantReply,
                                                                     byte[] specifics)
            throws TransportException {
        synchronized (globalReqPromises) {
            log.info("Making global request for `{}`", name);
            trans.write(new SSHPacket(Message.GLOBAL_REQUEST).putString(name)
                                                             .putBoolean(wantReply)
                                                             .putRawBytes(specifics));

            Promise<SSHPacket, ConnectionException> promise = null;
            if (wantReply) {
                promise = new Promise<SSHPacket, ConnectionException>("global req for " + name, ConnectionException.chainer);
                globalReqPromises.add(promise);
            }
            return promise;
        }
    }

    private void gotGlobalReqResponse(SSHPacket response)
            throws ConnectionException {
        synchronized (globalReqPromises) {
            Promise<SSHPacket, ConnectionException> gr = globalReqPromises.poll();
            if (gr == null)
                throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                              "Got a global request response when none was requested");
            else if (response == null)
                gr.deliverError(new ConnectionException("Global request [" + gr + "] failed"));
            else
                gr.deliver(response);
        }
    }

    private void gotChannelOpen(SSHPacket buf)
            throws ConnectionException, TransportException {
        try {
            final String type = buf.readString();
            log.debug("Received CHANNEL_OPEN for `{}` channel", type);
            if (openers.containsKey(type))
                openers.get(type).handleOpen(buf);
            else {
                log.warn("No opener found for `{}` CHANNEL_OPEN request -- rejecting", type);
                sendOpenFailure(buf.readUInt32AsInt(), Reason.UNKNOWN_CHANNEL_TYPE, "");
            }
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
    }

    @Override
    public void sendOpenFailure(int recipient, Reason reason, String message)
            throws TransportException {
        trans.write(new SSHPacket(Message.CHANNEL_OPEN_FAILURE)
                            .putUInt32(recipient)
                            .putUInt32(reason.getCode())
                            .putString(message));
    }

    @Override
    public void notifyError(SSHException error) {
        super.notifyError(error);
        synchronized (globalReqPromises) {
            ErrorDeliveryUtil.alertPromises(error, globalReqPromises);
            globalReqPromises.clear();
        }
        ErrorNotifiable.Util.alertAll(error, channels.values());
        channels.clear();
    }

}