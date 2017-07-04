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
package net.schmizz.sshj.transport;

import com.hierynomus.sshj.transport.IdentificationStringParser;
import net.schmizz.concurrent.ErrorDeliveryUtil;
import net.schmizz.concurrent.Event;
import net.schmizz.sshj.AbstractService;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.transport.verification.AlgorithmsVerifier;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A thread-safe {@link Transport} implementation.
 */
public final class TransportImpl
        implements Transport, DisconnectListener {

    private static final class NullService
            extends AbstractService {

        NullService(Transport trans) {
            super("null-service", trans);
        }

    }

    static final class ConnInfo {

        final String host;
        final int port;
        final InputStream in;
        final OutputStream out;

        ConnInfo(String host, int port, InputStream in, OutputStream out) {
            this.host = host;
            this.port = port;
            this.in = in;
            this.out = out;
        }

    }

    private final LoggerFactory loggerFactory;

    private final Logger log;

    private final Service nullService;

    private final Config config;

    private final KeyExchanger kexer;

    private final Reader reader;

    /**
     * @deprecated Moved to {@link net.schmizz.sshj.SSHClient}
     */
    @Deprecated
    private final SSHClient sshClient;

    private final Encoder encoder;

    private final Decoder decoder;

    private final Event<TransportException> serviceAccept;

    private final Event<TransportException> close;

    /**
     * Client version identification string
     */
    private final String clientID;

    private volatile int timeoutMs = 30 * 1000; // Crazy long, but it was the original default

    private volatile boolean authed = false;

    /**
     * Currently active service e.g. UserAuthService, ConnectionService
     */
    private volatile Service service;

    private DisconnectListener disconnectListener;

    private ConnInfo connInfo;

    /**
     * Server version identification string
     */
    private String serverID;

    /**
     * Message identifier of last packet received
     */
    private Message msg;

    private final ReentrantLock writeLock = new ReentrantLock();

    public TransportImpl(Config config) {
        this.config = config;
        this.loggerFactory = config.getLoggerFactory();
        this.serviceAccept = new Event<TransportException>("service accept", TransportException.chainer, loggerFactory);
        this.close = new Event<TransportException>("transport close", TransportException.chainer, loggerFactory);
        this.nullService = new NullService(this);
        this.service = nullService;
        this.log = loggerFactory.getLogger(getClass());
        this.disconnectListener = this;
        this.reader = new Reader(this);
        this.encoder = new Encoder(config.getRandomFactory().create(), writeLock, loggerFactory);
        this.decoder = new Decoder(this);
        this.kexer = new KeyExchanger(this);
        this.clientID = String.format("SSH-2.0-%s", config.getVersion());
        this.sshClient = null;
    }

    /*
     * Temporary constructor until we remove support for the set/get Heartbeat interval from transport.
     * @deprecated To be removed in 0.12.0
     */
    @Deprecated
    public TransportImpl(Config config, SSHClient sshClient) {
        this.config = config;
        this.loggerFactory = config.getLoggerFactory();
        this.serviceAccept = new Event<TransportException>("service accept", TransportException.chainer, loggerFactory);
        this.close = new Event<TransportException>("transport close", TransportException.chainer, loggerFactory);
        this.log = loggerFactory.getLogger(getClass());
        this.nullService = new NullService(this);
        this.service = nullService;
        this.disconnectListener = this;
        this.reader = new Reader(this);
        this.encoder = new Encoder(config.getRandomFactory().create(), writeLock, loggerFactory);
        this.decoder = new Decoder(this);
        this.kexer = new KeyExchanger(this);
        this.clientID = String.format("SSH-2.0-%s", config.getVersion());
        this.sshClient = sshClient;
    }

    @Override
    public void init(String remoteHost, int remotePort, InputStream in, OutputStream out)
            throws TransportException {
        connInfo = new ConnInfo(remoteHost, remotePort, in, out);

        try {

            if (config.isWaitForServerIdentBeforeSendingClientIdent()) {
                receiveServerIdent();
                sendClientIdent();
            } else {
                sendClientIdent();
                receiveServerIdent();
            }


            log.info("Server identity string: {}", serverID);

        } catch (IOException e) {
            throw new TransportException(e);
        }

        reader.start();
    }

    /**
     * TransportImpl implements its own default DisconnectListener.
     */
    @Override
    public void notifyDisconnect(DisconnectReason reason, String message) {
        log.info("Disconnected - {}", reason);
    }

    private void receiveServerIdent() throws IOException {
        final Buffer.PlainBuffer buf = new Buffer.PlainBuffer();
        while ((serverID = readIdentification(buf)).isEmpty()) {
            int b = connInfo.in.read();
            if (b == -1) {
                log.error("Received end of connection, but no identification received. ");
                throw new TransportException("Server closed connection during identification exchange");

            }
            buf.putByte((byte) b);
        }
    }

    /**
     * Receive the server identification string.
     *
     * @throws IOException If there was an error writing to the outputstream.
     */
    private void sendClientIdent() throws IOException {
        log.info("Client identity string: {}", clientID);
        connInfo.out.write((clientID + "\r\n").getBytes(IOUtils.UTF8));
        connInfo.out.flush();
    }

    /**
     * Reads the identification string from the SSH server. This is the very first string that is sent upon connection
     * by the server. It takes the form of, e.g. "SSH-2.0-OpenSSH_ver".
     * <p/>
     * Several concerns are taken care of here, e.g. verifying protocol version, correct line endings as specified in
     * RFC and such.
     * <p/>
     * This is not efficient but is only done once.
     *
     * @param buffer The buffer to read from.
     * @return empty string if full ident string has not yet been received
     * @throws IOException
     */
    private String readIdentification(Buffer.PlainBuffer buffer)
            throws IOException {
        String ident = new IdentificationStringParser(buffer, loggerFactory).parseIdentificationString();
        if (ident.isEmpty()) {
            return ident;
        }

        if (!ident.startsWith("SSH-2.0-") && !ident.startsWith("SSH-1.99-"))
            throw new TransportException(DisconnectReason.PROTOCOL_VERSION_NOT_SUPPORTED,
                    "Server does not support SSHv2, identified as: " + ident);

        return ident;
    }

    @Override
    public void addHostKeyVerifier(HostKeyVerifier hkv) {
        kexer.addHostKeyVerifier(hkv);
    }

    @Override
    public void addAlgorithmsVerifier(AlgorithmsVerifier verifier) {
        kexer.addAlgorithmsVerifier(verifier);
    }

    @Override
    public void doKex()
            throws TransportException {
        kexer.startKex(true);
    }

    public boolean isKexDone() {
        return kexer.isKexDone();
    }

    @Override
    public int getTimeoutMs() {
        return timeoutMs;
    }

    @Override
    public void setTimeoutMs(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    @Override
    @Deprecated
    public int getHeartbeatInterval() {
        log.warn("**Deprecated**: Please use: sshClient.getConnection().getKeepAlive().getKeepAliveInterval()");
        return sshClient.getConnection().getKeepAlive().getKeepAliveInterval();
    }

    @Override
    @Deprecated
    public void setHeartbeatInterval(int interval) {
        log.warn("**Deprecated**: Please use: sshClient.getConnection().getKeepAlive().setKeepAliveInterval()");
        sshClient.getConnection().getKeepAlive().setKeepAliveInterval(interval);
    }

    @Override
    public String getRemoteHost() {
        return connInfo.host;
    }

    @Override
    public int getRemotePort() {
        return connInfo.port;
    }

    @Override
    public String getClientVersion() {
        return clientID.substring(8);
    }

    @Override
    public Config getConfig() {
        return config;
    }

    @Override
    public String getServerVersion() {
        return serverID == null ? null : serverID.substring(8);
    }

    @Override
    public byte[] getSessionID() {
        return kexer.getSessionID();
    }

    @Override
    public synchronized Service getService() {
        return service;
    }

    @Override
    public synchronized void setService(Service service) {
        if (service == null)
            service = nullService;

        log.debug("Setting active service to {}", service.getName());
        this.service = service;
    }

    @Override
    public void reqService(Service service)
            throws TransportException {
        serviceAccept.lock();
        try {
            serviceAccept.clear();
            sendServiceRequest(service.getName());
            serviceAccept.await(timeoutMs, TimeUnit.MILLISECONDS);
            setService(service);
        } finally {
            serviceAccept.unlock();
        }
    }

    /**
     * Sends a service request for the specified service
     *
     * @param serviceName name of the service being requested
     * @throws TransportException if there is an error while sending the request
     */
    private void sendServiceRequest(String serviceName)
            throws TransportException {
        log.debug("Sending SSH_MSG_SERVICE_REQUEST for {}", serviceName);
        write(new SSHPacket(Message.SERVICE_REQUEST).putString(serviceName));
    }

    @Override
    public void setAuthenticated() {
        this.authed = true;
        encoder.setAuthenticated();
        decoder.setAuthenticated();
    }

    @Override
    public boolean isAuthenticated() {
        return authed;
    }

    @Override
    public long sendUnimplemented()
            throws TransportException {
        final long seq = decoder.getSequenceNumber();
        log.debug("Sending SSH_MSG_UNIMPLEMENTED for packet #{}", seq);
        return write(new SSHPacket(Message.UNIMPLEMENTED).putUInt32(seq));
    }

    @Override
    public void join()
            throws TransportException {
        close.await();
    }

    @Override
    public void join(int timeout, TimeUnit unit)
            throws TransportException {
        close.await(timeout, unit);
    }

    @Override
    public boolean isRunning() {
        return reader.isAlive() && !close.isSet();
    }

    @Override
    public void disconnect() {
        disconnect(DisconnectReason.BY_APPLICATION);
    }

    @Override
    public void disconnect(DisconnectReason reason) {
        disconnect(reason, "");
    }

    @Override
    public void disconnect(DisconnectReason reason, String message) {
        close.lock();
        try {
            if (isRunning()) {
                disconnectListener.notifyDisconnect(reason, message);
                getService().notifyError(new TransportException(reason, "Disconnected"));
                sendDisconnect(reason, message);
                finishOff();
                close.set();
            }
        } finally {
            close.unlock();
        }
    }

    @Override
    public void setDisconnectListener(DisconnectListener listener) {
        this.disconnectListener = listener == null ? this : listener;
    }

    @Override
    public DisconnectListener getDisconnectListener() {
        return disconnectListener;
    }

    @Override
    public long write(SSHPacket payload)
            throws TransportException {
        writeLock.lock();
        try {

            if (kexer.isKexOngoing()) {
                // Only transport layer packets (1 to 49) allowed except SERVICE_REQUEST
                final Message m = Message.fromByte(payload.array()[payload.rpos()]);
                if (!m.in(1, 49) || m == Message.SERVICE_REQUEST) {
                    assert m != Message.KEXINIT;
                    kexer.waitForDone();
                }
            } else if (encoder.getSequenceNumber() == 0) // We get here every 2**32th packet
                kexer.startKex(true);

            final long seq = encoder.encode(payload);
            try {
                connInfo.out.write(payload.array(), payload.rpos(), payload.available());
                connInfo.out.flush();
            } catch (IOException ioe) {
                throw new TransportException(ioe);
            }

            return seq;

        } finally {
            writeLock.unlock();
        }
    }

    private void sendDisconnect(DisconnectReason reason, String message) {
        if (message == null)
            message = "";
        log.debug("Sending SSH_MSG_DISCONNECT: reason=[{}], msg=[{}]", reason, message);
        try {
            write(new SSHPacket(Message.DISCONNECT)
                    .putUInt32(reason.toInt())
                    .putString(message)
                    .putString(""));
        } catch (IOException worthless) {
            log.debug("Error writing packet: {}", worthless.toString());
        }
    }

    /**
     * This is where all incoming packets are handled. If they pertain to the transport layer, they are handled here;
     * otherwise they are delegated to the active service instance if any via {@link Service#handle}.
     * <p/>
     * Even among the transport layer specific packets, key exchange packets are delegated to {@link
     * KeyExchanger#handle}.
     * <p/>
     * This method is called in the context of the {@link #reader} thread via {@link Decoder#received} when a full
     * packet has been decoded.
     *
     * @param msg the message identifer
     * @param buf buffer containg rest of the packet
     * @throws SSHException if an error occurs during handling (unrecoverable)
     */
    @Override
    public void handle(Message msg, SSHPacket buf)
            throws SSHException {
        this.msg = msg;

        log.trace("Received packet {}", msg);

        if (msg.geq(50)) // not a transport layer packet
            service.handle(msg, buf);

        else if (msg.in(20, 21) || msg.in(30, 49)) // kex packet
            kexer.handle(msg, buf);

        else
            switch (msg) {
                case DISCONNECT:
                    gotDisconnect(buf);
                    break;
                case IGNORE:
                    log.debug("Received SSH_MSG_IGNORE");
                    break;
                case UNIMPLEMENTED:
                    gotUnimplemented(buf);
                    break;
                case DEBUG:
                    gotDebug(buf);
                    break;
                case SERVICE_ACCEPT:
                    gotServiceAccept();
                    break;
                case USERAUTH_BANNER:
                    log.debug("Received USERAUTH_BANNER");
                    break;
                default:
                    sendUnimplemented();
                    break;
            }
    }

    private void gotDebug(SSHPacket buf)
            throws TransportException {
        try {
            final boolean display = buf.readBoolean();
            final String message = buf.readString();
            log.debug("Received SSH_MSG_DEBUG (display={}) '{}'", display, message);
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }
    }

    private void gotDisconnect(SSHPacket buf)
            throws TransportException {
        try {
            final DisconnectReason code = DisconnectReason.fromInt(buf.readUInt32AsInt());
            final String message = buf.readString();
            log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, message);
            throw new TransportException(code, message);
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }
    }

    private void gotServiceAccept()
            throws TransportException {
        serviceAccept.lock();
        try {
            if (!serviceAccept.hasWaiters())
                throw new TransportException(DisconnectReason.PROTOCOL_ERROR,
                        "Got a service accept notification when none was awaited");
            serviceAccept.set();
        } finally {
            serviceAccept.unlock();
        }
    }

    /**
     * Got an SSH_MSG_UNIMPLEMENTED, so lets see where we're at and act accordingly.
     *
     * @param packet The 'unimplemented' packet received
     * @throws TransportException
     */
    private void gotUnimplemented(SSHPacket packet)
            throws SSHException {
        long seqNum = packet.readUInt32();
        log.debug("Received SSH_MSG_UNIMPLEMENTED #{}", seqNum);
        if (kexer.isKexOngoing())
            throw new TransportException("Received SSH_MSG_UNIMPLEMENTED while exchanging keys");
        getService().notifyUnimplemented(seqNum);
    }

    private void finishOff() {
        reader.interrupt();
        IOUtils.closeQuietly(connInfo.in);
        IOUtils.closeQuietly(connInfo.out);
    }

    public void die(Exception ex) {
        close.lock();
        try {
            if (!close.isSet()) {

                log.error("Dying because - {}", ex.getMessage(), ex);

                final SSHException causeOfDeath = SSHException.chainer.chain(ex);

                disconnectListener.notifyDisconnect(causeOfDeath.getDisconnectReason(), causeOfDeath.getMessage());

                ErrorDeliveryUtil.alertEvents(causeOfDeath, close, serviceAccept);
                kexer.notifyError(causeOfDeath);
                getService().notifyError(causeOfDeath);
                setService(nullService);

                { // Perhaps can send disconnect packet to server
                    final boolean didNotReceiveDisconnect = msg != Message.DISCONNECT;
                    final boolean gotRequiredInfo = causeOfDeath.getDisconnectReason() != DisconnectReason.UNKNOWN;
                    if (didNotReceiveDisconnect && gotRequiredInfo)
                        sendDisconnect(causeOfDeath.getDisconnectReason(), causeOfDeath.getMessage());
                }

                finishOff();

                close.set();
            }
        } finally {
            close.unlock();
        }
    }

    String getClientID() {
        return clientID;
    }

    String getServerID() {
        return serverID;
    }

    Encoder getEncoder() {
        return encoder;
    }

    Decoder getDecoder() {
        return decoder;
    }

    ReentrantLock getWriteLock() {
        return writeLock;
    }

    ConnInfo getConnInfo() {
        return connInfo;
    }

}
