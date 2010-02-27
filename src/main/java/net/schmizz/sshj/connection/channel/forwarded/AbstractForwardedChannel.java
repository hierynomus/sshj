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
package net.schmizz.sshj.connection.channel.forwarded;

import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.channel.AbstractChannel;
import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.connection.channel.OpenFailException.Reason;
import net.schmizz.sshj.transport.TransportException;

/** Base class for forwarded channels whose open is initiated by the server. */
public abstract class AbstractForwardedChannel extends AbstractChannel implements Channel.Forwarded {

    protected final String origIP;
    protected final int origPort;

    /*
    * First 2 args are standard; the others can be parsed from a CHANNEL_OPEN packet.
    */

    protected AbstractForwardedChannel(String type, Connection conn, int recipient, int remoteWinSize,
                                       int remoteMaxPacketSize, String origIP, int origPort) {
        super(type, conn);
        this.origIP = origIP;
        this.origPort = origPort;
        init(recipient, remoteWinSize, remoteMaxPacketSize);
    }

    public void confirm() throws TransportException {
        log.info("Confirming `{}` channel #{}", getType(), getID());
        // Must ensure channel is attached before confirming, data could start coming in immediately!
        conn.attach(this);
        trans.write(newBuffer(Message.CHANNEL_OPEN_CONFIRMATION)
                .putInt(getID())
                .putInt(getLocalWinSize())
                .putInt(getLocalMaxPacketSize()));
        open.set();
    }

    public void reject(Reason reason, String message) throws TransportException {
        log.info("Rejecting `{}` channel: {}", getType(), message);
        conn.sendOpenFailure(getRecipient(), reason, message);
    }

    public String getOriginatorIP() {
        return origIP;
    }

    public int getOriginatorPort() {
        return origPort;
    }

}