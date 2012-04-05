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
package net.schmizz.sshj.connection.channel;

import net.schmizz.sshj.common.ErrorNotifiable;
import net.schmizz.sshj.common.SSHPacketHandler;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.transport.TransportException;

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

/** A channel is the basic medium for application-layer data on top of an SSH transport. */
public interface Channel
        extends Closeable, SSHPacketHandler, ErrorNotifiable {

    /** Direct channels are those that are initiated by us. */
    interface Direct
            extends Channel {

        /**
         * Request opening this channel from remote end.
         *
         * @throws OpenFailException   in case the channel open request was rejected
         * @throws ConnectionException other connection-layer error
         * @throws TransportException  error writing packets etc.
         */
        void open()
                throws ConnectionException, TransportException;

    }

    /** Forwarded channels are those that are initiated by the server. */
    interface Forwarded
            extends Channel {

        /**
         * Confirm {@code CHANNEL_OPEN} request.
         *
         * @throws TransportException error sending confirmation packet
         */
        void confirm()
                throws TransportException;

        /** @return the IP of where the forwarded connection originates. */
        String getOriginatorIP();

        /** @return port from which the forwarded connection originates. */
        int getOriginatorPort();

        /**
         * Indicate rejection to remote end.
         *
         * @param reason  indicate {@link OpenFailException.Reason reason} for rejection of the request
         * @param message indicate a message for why the request is rejected
         *
         * @throws TransportException error sending rejection packet
         */
        void reject(OpenFailException.Reason reason, String message)
                throws TransportException;

    }


    /** Close this channel. */
    @Override
    void close()
            throws TransportException, ConnectionException;

    /**
     * @return whether auto-expansion of local window is set.
     *
     * @see #setAutoExpand(boolean)
     */
    boolean getAutoExpand();

    /** @return the channel ID */
    int getID();

    /** @return the {@code InputStream} for this channel. */
    InputStream getInputStream();

    /** @return the maximum packet size that we have specified. */
    int getLocalMaxPacketSize();

    /** @return the current local window size. */
    long getLocalWinSize();

    /** @return an {@code OutputStream} for this channel. */
    OutputStream getOutputStream();

    /** @return the channel ID at the remote end. */
    int getRecipient();

    /** @return the maximum packet size as specified by the remote end. */
    int getRemoteMaxPacketSize();

    /** @return the current remote window size. */
    long getRemoteWinSize();

    /** @return the channel type identifier. */
    String getType();

    /** @return whether the channel is open. */
    boolean isOpen();

    /**
     * Sends an EOF message to the server for this channel; indicating that no more data will be sent by us. The {@code
     * OutputStream} for this channel will be closed and no longer usable.
     *
     * @throws TransportException if there is an error sending the EOF message
     */
    void sendEOF()
            throws TransportException;

    /**
     * Set whether local window should automatically expand when data is received, irrespective of whether data has been
     * read from that stream. This is useful e.g. when a remote command produces a lot of output that would fill the
     * local window but you are not interested in reading from its {@code InputStream}.
     *
     * @param autoExpand whether local windows should automatically expand
     */
    void setAutoExpand(boolean autoExpand);

    void join()
            throws ConnectionException;

    void join(int timeout, TimeUnit unit)
            throws ConnectionException;

}
