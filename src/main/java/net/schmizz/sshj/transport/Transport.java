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
package net.schmizz.sshj.transport;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.SSHPacketHandler;
import net.schmizz.sshj.transport.verification.HostKeyVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Transport layer of the SSH protocol. */
public interface Transport extends SSHPacketHandler {

    /**
     * Sets the {@code socket} to be used by this transport; and identification information is exchanged. A {@link
     * TransportException} is thrown in case of SSH protocol version incompatibility.
     *
     * @throws TransportException if there is an error during exchange of identification information
     */
    void init(String host, int port, InputStream in, OutputStream out) throws TransportException;

    void addHostKeyVerifier(HostKeyVerifier hkv);

    void doKex() throws TransportException;

    /** @return the version string used by this client to identify itself to an SSH server, e.g. "SSHJ_3_0" */
    String getClientVersion();

    /** @return the {@link net.schmizz.sshj.ConfigImpl} associated with this transport. */
    Config getConfig();

    /** @return the timeout that is currently set for blocking operations. */
    int getTimeout();

    /**
     * Set a timeout for method that may block, e.g. {@link #reqService(net.schmizz.sshj.Service)}, {@link
     * KeyExchanger#waitForDone()}.
     *
     * @param timeout the timeout in seconds
     */
    void setTimeout(int timeout);

    int getHeartbeatInterval();

    void setHeartbeatInterval(int interval);

    /** Returns the hostname to which this transport is connected. */
    String getRemoteHost();

    /** Returns the port number on the {@link #getRemoteHost() remote host} to which this transport is connected. */
    int getRemotePort();

    /**
     * Returns the version string as sent by the SSH server for identification purposes, e.g. "OpenSSH_$version".
     * <p/>
     * If the transport has not yet been initialized via {@link #init}, it will be {@code null}.
     *
     * @return server's version string (may be {@code null})
     */
    String getServerVersion();

    byte[] getSessionID();

    /** Returns the currently active {@link net.schmizz.sshj.Service} instance. */
    Service getService();

    /**
     * Request a SSH service represented by a {@link net.schmizz.sshj.Service} instance. A separate call to {@link
     * #setService} is not needed.
     *
     * @param service the SSH service to be requested
     *
     * @throws IOException if the request failed for any reason
     */
    void reqService(Service service) throws TransportException;

    /**
     * Sets the currently active {@link net.schmizz.sshj.Service}. Handling of non-transport-layer packets is {@link
     * net.schmizz.sshj.Service#handle delegated} to that service.
     * <p/>
     * For this method to be successful, at least one service request via {@link #reqService} must have been successful
     * (not necessarily for the service being set).
     *
     * @param service (null-ok) the {@link net.schmizz.sshj.Service}
     */
    void setService(Service service);

    /** Returns whether the transport thinks it is authenticated. */
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
    long sendUnimplemented() throws TransportException;

    /**
     * Returns whether this transport is active.
     * <p/>
     * The transport is considered to be running if it has been initialized without error via {@link #init} and has not
     * been disconnected.
     */
    boolean isRunning();

    /**
     * Joins the thread calling this method to the transport's death. The transport dies of exceptional events.
     *
     * @throws TransportException
     */
    void join() throws TransportException;

    /** Send a disconnection packet with reason as {@link DisconnectReason#BY_APPLICATION}, and closes this transport. */
    void disconnect();

    /**
     * Send a disconnect packet with the given {@link net.schmizz.sshj.common.DisconnectReason reason}, and closes this
     * transport.
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
     * The {@code payload} {@link net.schmizz.sshj.common.SSHPacket} should have 5 bytes free at the beginning to avoid
     * a performance penalty associated with making space for header bytes (packet length, padding length).
     *
     * @param payload the {@link net.schmizz.sshj.common.SSHPacket} containing data to send
     *
     * @return sequence number of the sent packet
     *
     * @throws TransportException if an error occurred sending the packet
     */
    long write(SSHPacket payload) throws TransportException;
}