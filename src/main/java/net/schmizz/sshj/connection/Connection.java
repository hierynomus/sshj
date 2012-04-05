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

import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.connection.channel.OpenFailException;
import net.schmizz.sshj.connection.channel.forwarded.ForwardedChannelOpener;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;

/** Connection layer of the SSH protocol. Refer to RFC 254. */
public interface Connection {

    /**
     * Attach a {@link Channel} to this connection. A channel must be attached to the connection if it is to receive any
     * channel-specific data that is received.
     *
     * @param chan the channel
     */
    void attach(Channel chan);

    /**
     * Attach a {@link ForwardedChannelOpener} to this connection, which will be delegated opening of any {@code
     * CHANNEL_OPEN} packets {@link ForwardedChannelOpener#getChannelType() for which it is responsible}.
     *
     * @param opener an opener for forwarded channels
     */
    void attach(ForwardedChannelOpener opener);

    /**
     * Forget an attached {@link Channel}.
     *
     * @param chan the channel
     */
    void forget(Channel chan);

    /**
     * Forget an attached {@link ForwardedChannelOpener}.
     *
     * @param opener the opener to forget
     */
    void forget(ForwardedChannelOpener opener);

    /**
     * @param id number of the channel to retrieve
     *
     * @return an attached {@link Channel} of specified channel number, or {@code null} if no such channel was attached
     */
    Channel get(int id);

    /**
     * Wait for the situation that no channels are attached (e.g., got closed).
     *
     * @throws InterruptedException if the thread is interrupted
     */
    void join()
            throws InterruptedException;

    /**
     * @param chanType channel type
     *
     * @return an attached {@link ForwardedChannelOpener} of specified channel-type, or {@code null} if no such channel
     *         was attached
     */
    ForwardedChannelOpener get(String chanType);

    /** @return an available ID a {@link Channel} can rightfully claim. */
    int nextID();

    /**
     * Send an SSH global request.
     *
     * @param name      request name
     * @param wantReply whether a reply is requested
     * @param specifics {@link SSHPacket} containing fields specific to the request
     *
     * @return a {@link net.schmizz.concurrent.Promise} for the reply data (in case {@code wantReply} is true) which
     *         allows waiting on the reply, or {@code null} if a reply is not requested.
     *
     * @throws TransportException if there is an error sending the request
     */
    public Promise<SSHPacket, ConnectionException> sendGlobalRequest(String name, boolean wantReply,
                                                                     byte[] specifics)
            throws TransportException;

    /**
     * Send a {@code SSH_MSG_OPEN_FAILURE} for specified {@code Reason} and {@code message}.
     *
     * @param recipient number of the recipient channel
     * @param reason    a reason for the failure
     * @param message   an explanatory message
     *
     * @throws TransportException if there is a transport-layer error
     */
    void sendOpenFailure(int recipient, OpenFailException.Reason reason, String message)
            throws TransportException;

    /**
     * @return the maximum packet size for the local window this connection recommends to any {@link Channel}'s that ask
     *         for it.
     */
    int getMaxPacketSize();

    /**
     * Set the maximum packet size for the local window this connection recommends to any {@link Channel}'s that ask for
     * it.
     *
     * @param maxPacketSize maximum packet size in bytes
     */
    void setMaxPacketSize(int maxPacketSize);

    /** @return the size for the local window this connection recommends to any {@link Channel}'s that ask for it. */
    long getWindowSize();

    /**
     * Set the size for the local window this connection recommends to any {@link Channel}'s that ask for it.
     *
     * @param windowSize window size in bytes
     */
    void setWindowSize(long windowSize);

    /** @return the associated {@link Transport}. */
    Transport getTransport();

    /**
     * @return the {@code timeout} in seconds that this connection uses for blocking operations and recommends to any
     *         {@link Channel other} {@link ForwardedChannelOpener classes} that ask for it.
     */
    int getTimeout();

    /**
     * Set the {@code timeout} this connection uses for blocking operations and recommends to any {@link Channel other}
     * {@link ForwardedChannelOpener classes} that ask for it.
     *
     * @param timeout timeout in seconds
     */
    void setTimeout(int timeout);
}