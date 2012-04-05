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
package net.schmizz.sshj.connection.channel.direct;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.AbstractChannel;
import net.schmizz.sshj.connection.channel.Channel;
import net.schmizz.sshj.connection.channel.OpenFailException;
import net.schmizz.sshj.transport.TransportException;

import java.util.concurrent.TimeUnit;

/** Base class for direct channels whose open is initated by the client. */
public abstract class AbstractDirectChannel
        extends AbstractChannel
        implements Channel.Direct {

    protected AbstractDirectChannel(Connection conn, String type) {
        super(conn, type);

        /*
        * We expect to receive channel open confirmation/rejection and want to be able to next this packet.
        */
        conn.attach(this);
    }

    @Override
    public void open()
            throws ConnectionException, TransportException {
        trans.write(buildOpenReq());
        open.await(conn.getTimeout(), TimeUnit.SECONDS);
    }

    private void gotOpenConfirmation(SSHPacket buf)
            throws ConnectionException {
        try {
            init(buf.readUInt32AsInt(), buf.readUInt32(), buf.readUInt32());
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
        open.set();
    }

    private void gotOpenFailure(SSHPacket buf)
            throws ConnectionException {
        try {
            open.deliverError(new OpenFailException(getType(), buf.readUInt32AsInt(), buf.readString()));
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
        finishOff();
    }

    protected SSHPacket buildOpenReq() {
        return new SSHPacket(Message.CHANNEL_OPEN)
                .putString(getType())
                .putUInt32(getID())
                .putUInt32(getLocalWinSize())
                .putUInt32(getLocalMaxPacketSize());
    }

    @Override
    protected void gotUnknown(Message cmd, SSHPacket buf)
            throws ConnectionException, TransportException {
        switch (cmd) {

            case CHANNEL_OPEN_CONFIRMATION:
                gotOpenConfirmation(buf);
                break;

            case CHANNEL_OPEN_FAILURE:
                gotOpenFailure(buf);
                break;

            default:
                super.gotUnknown(cmd, buf);
        }
    }

}