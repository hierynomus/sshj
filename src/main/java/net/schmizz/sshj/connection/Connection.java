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
package net.schmizz.sshj.connection;

import net.schmizz.concurrent.Future;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.connection.channel.OpenFailException;
import net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;

/**
 * Connection layer of the SSH protocol.
 *
 * @see rfc4254
 */
public interface Connection {

    /**
     * Attach a {@link net.schmizz.sshj.connection.channel.Channel} to this connection. A channel must be attached to
     * the connection if it is to receive any channel-specific data that is received.
     */
    void attach(Channel chan);

    /**
     * Attach a {@link net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener} to this connection, which
     * will be delegated opening of any {@code CHANNEL_OPEN} packets {@link net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener#getChannelType()
     * for which it is responsible}.
     */
    void attach(ForwardedChannelOpener opener);

    /** Forget an attached {@link Channel}. */
    void forget(Channel chan);

    /** Forget an attached {@link net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener}. */
    void forget(ForwardedChannelOpener handler);

    /** Returns an attached {@link Channel} of specified channel-id, or {@code null} if no such channel was attached */
    Channel get(int id);

    /** Wait for the situation that no channels are attached (e.g., got closed). */
    void join() throws InterruptedException;

    /**
     * Returns an attached {@link net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener} of specified
     * channel-type, or {@code null} if no such channel was attached
     */
    ForwardedChannelOpener get(String chanType);

    /** Returns an available ID a {@link net.schmizz.sshj.connection.channel.Channel} can rightfully claim. */
    int nextID();

    /**
     * Send an SSH global request.
     *
     * @param name      request name
     * @param wantReply whether a reply is requested
     * @param specifics {@link net.schmizz.sshj.common.SSHPacket} containing fields specific to the request
     *
     * @return a {@link net.schmizz.concurrent.Future} for the reply data (in case {@code wantReply} is true) which
     *         allows waiting on the reply, or {@code null} if a reply is not requested.
     *
     * @throws TransportException if there is an error sending the request
     */
    public Future<SSHPacket, ConnectionException> sendGlobalRequest(String name, boolean wantReply,
                                                                    Buffer.PlainBuffer specifics) throws TransportException;

    /**
     * Send a {@code SSH_MSG_OPEN_FAILURE} for specified {@code Reason} and {@code message}.
     *
     * @param recipient
     * @param reason
     * @param message
     *
     * @throws TransportException
     */
    void sendOpenFailure(int recipient, OpenFailException.Reason reason, String message) throws TransportException;

    /**
     * Get the maximum packet size for the local window this connection recommends to any {@link Channel}'s that ask for
     * it.
     */
    int getMaxPacketSize();

    /**
     * Set the maximum packet size for the local window this connection recommends to any {@link Channel}'s that ask for
     * it.
     */
    void setMaxPacketSize(int maxPacketSize);

    /**
     * Get the size for the local window this connection recommends to any {@link net.schmizz.sshj.connection.channel.Channel}'s
     * that ask for it.
     */
    int getWindowSize();

    /** Set the size for the local window this connection recommends to any {@link Channel}'s that ask for it. */
    void setWindowSize(int windowSize);

    /** Get the associated {@link Transport}. */
    Transport getTransport();

    /**
     * Get the {@code timeout} this connection uses for blocking operations and recommends to any {@link Channel other}
     * {@link net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener classes} that ask for it.
     */
    int getTimeout();

    /**
     * Set the {@code timeout} this connection uses for blocking operations and recommends to any {@link
     * net.schmizz.sshj.connection.channel.Channel other} {@link net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener
     * classes} that ask for it.
     */
    void setTimeout(int timeout);
}