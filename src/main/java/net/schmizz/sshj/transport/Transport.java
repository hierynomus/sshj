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
package net.schmizz.sshj.transport;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.SSHPacketHandler;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

/** Transport layer of the SSH protocol. */
public interface Transport
        extends SSHPacketHandler {

    /**
     * Sets the host information and the streams to be used by this transport. Identification information is exchanged
     * with the server. A {@link TransportException} is thrown in case of SSH protocol version incompatibility.
     *
     * @param host server's hostname
     * @param port server's port
     * @param in   input stream for the connection
     * @param out  output stream for the connection
     *
     * @throws TransportException if there is an error during exchange of identification information
     */
    void init(String host, int port, InputStream in, OutputStream out)
            throws TransportException;

    /**
     * Adds the specified verifier.
     *
     * @param hkv the host key verifier
     */
    void addHostKeyVerifier(HostKeyVerifier hkv);

    /**
     * Do key exchange and algorithm negotiation. This can be the initial one or for algorithm renegotiation.
     *
     * @throws TransportException if there was an error during key exchange
     */
    void doKex()
            throws TransportException;

    /** @return the version string used by this client to identify itself to an SSH server, e.g. "SSHJ_3_0" */
    String getClientVersion();

    /** @return the {@link Config} associated with this transport. */
    Config getConfig();

    /** @return the timeout that is currently set for blocking operations. */
    int getTimeout();

    /**
     * Set a timeout for methods that may block.
     *
     * @param timeout the timeout in seconds
     */
    void setTimeout(int timeout);

    /** @return the interval in seconds at which a heartbeat message is sent to the server */
    int getHeartbeatInterval();

    /** @param interval the interval in seconds, {@code 0} means no hearbeat */
    void setHeartbeatInterval(int interval);

    /** @return the hostname to which this transport is connected. */
    String getRemoteHost();

    /** @return the port number on the remote host to which this transport is connected. */
    int getRemotePort();

    /**
     * Returns the version string as sent by the SSH server for identification purposes, e.g. "OpenSSH_$version".
     * <p/>
     * If the transport has not yet been initialized via {@link #init}, it will be {@code null}.
     *
     * @return server's version string (may be {@code null})
     */
    String getServerVersion();

    /** @return the session identifier assigned by server */
    byte[] getSessionID();

    /** @return the currently active {@link Service} instance. */
    Service getService();

    /**
     * Request a SSH service represented by a {@link Service} instance. A separate call to {@link #setService} is not
     * needed.
     *
     * @param service the SSH service to be requested
     *
     * @throws TransportException if the request failed for any reason
     */
    void reqService(Service service)
            throws TransportException;

    /**
     * Sets the currently active {@link Service}. Handling of non-transport-layer packets is {@link Service#handle
     * delegated} to that service.
     * <p/>
     * For this method to be successful, at least one service request via {@link #reqService} must have been successful
     * (not necessarily for the service being set).
     *
     * @param service (null-ok) the {@link Service}
     */
    void setService(Service service);

    /** @return whether the transport thinks it is authenticated. */
    boolean isAuthenticated();

    /**
     * Informs this transport that authentication has been completed. This method <strong>must</strong> be called after
     * successful authentication, so that delayed compression may become effective if applicable.
     */
    void setAuthenticated();

    /**
     * Sends SSH_MSG_UNIMPLEMENTED in response to the last packet received.
     *
     * @return the sequence number of the packet sent
     *
     * @throws TransportException if an error occured sending the packet
     */
    long sendUnimplemented()
            throws TransportException;

    /**
     * @return whether this transport is active.
     *         <p/>
     *         The transport is considered to be running if it has been initialized without error via {@link #init} and
     *         has not been disconnected.
     */
    boolean isRunning();

    /**
     * Joins the thread calling this method to the transport's death.
     *
     * @throws TransportException if the transport dies of an exception
     */
    void join()
            throws TransportException;

    /**
     * Joins the thread calling this method to the transport's death.
     *
     * @throws TransportException if the transport dies of an exception
     */
    void join(int timeout, TimeUnit unit)
            throws TransportException;

    /** Send a disconnection packet with reason as {@link DisconnectReason#BY_APPLICATION}, and closes this transport. */
    void disconnect();

    /**
     * Send a disconnect packet with the given {@link DisconnectReason reason}, and closes this transport.
     *
     * @param reason reason for disconnecting
     */
    void disconnect(DisconnectReason reason);

    /**
     * Send a disconnect packet with the given {@link DisconnectReason reason} and {@code message}, and closes this
     * transport.
     *
     * @param reason  the reason code for this disconnect
     * @param message the text message
     */
    void disconnect(DisconnectReason reason, String message);

    /**
     * Write a packet over this transport.
     * <p/>
     * The {@code payload} {@link SSHPacket} should have 5 bytes free at the beginning to avoid a performance penalty
     * associated with making space for header bytes (packet length, padding length).
     *
     * @param payload the {@link SSHPacket} containing data to send
     *
     * @return sequence number of the sent packet
     *
     * @throws TransportException if an error occurred sending the packet
     */
    long write(SSHPacket payload)
            throws TransportException;

    /**
     * Specify a {@code listener} that will be notified upon disconnection.
     *
     * @param listener
     */
    void setDisconnectListener(DisconnectListener listener);

    /** @return the current disconnect listener. */
    DisconnectListener getDisconnectListener();

}