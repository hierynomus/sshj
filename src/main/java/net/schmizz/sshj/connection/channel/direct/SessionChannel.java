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
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.ChannelInputStream;
import net.schmizz.sshj.transport.TransportException;

import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** {@link Session} implementation. */
public class SessionChannel
        extends AbstractDirectChannel
        implements Session, Session.Command, Session.Shell, Session.Subsystem {

    private final ChannelInputStream err = new ChannelInputStream(this, trans, lwin);

    private Integer exitStatus;

    private Signal exitSignal;
    private Boolean wasCoreDumped;
    private String exitErrMsg;

    private Boolean canDoFlowControl;

    private boolean usedUp;

    public SessionChannel(Connection conn) {
        super(conn, "session");
    }

    @Override
    public void allocateDefaultPTY()
            throws ConnectionException, TransportException {
        allocatePTY("vt100", 80, 24, 0, 0, Collections.<PTYMode, Integer>emptyMap());
    }

    @Override
    public void allocatePTY(String term, int cols, int rows, int width, int height, Map<PTYMode, Integer> modes)
            throws ConnectionException, TransportException {
        sendChannelRequest(
                "pty-req",
                true,
                new Buffer.PlainBuffer()
                        .putString(term)
                        .putUInt32(cols)
                        .putUInt32(rows)
                        .putUInt32(width)
                        .putUInt32(height)
                        .putBytes(PTYMode.encode(modes))
        ).await(conn.getTimeout(), TimeUnit.SECONDS);
    }

    @Override
    public Boolean canDoFlowControl() {
        return canDoFlowControl;
    }

    @Override
    public void changeWindowDimensions(int cols, int rows, int width, int height)
            throws TransportException {
        sendChannelRequest(
                "window-change",
                false,
                new Buffer.PlainBuffer()
                        .putUInt32(cols)
                        .putUInt32(rows)
                        .putUInt32(width)
                        .putUInt32(height)
        );
    }

    @Override
    public Command exec(String command)
            throws ConnectionException, TransportException {
        checkReuse();
        log.info("Will request to exec `{}`", command);
        sendChannelRequest("exec", true, new Buffer.PlainBuffer().putString(command))
                .await(conn.getTimeout(), TimeUnit.SECONDS);
        usedUp = true;
        return this;
    }

    @Override
    public InputStream getErrorStream() {
        return err;
    }

    @Override
    public String getExitErrorMessage() {
        return exitErrMsg;
    }

    @Override
    public Signal getExitSignal() {
        return exitSignal;
    }

    @Override
    public Integer getExitStatus() {
        return exitStatus;
    }

    @Override
    public void handleRequest(String req, SSHPacket buf)
            throws ConnectionException, TransportException {
        try {
            if ("xon-xoff".equals(req))
                canDoFlowControl = buf.readBoolean();
            else if ("exit-status".equals(req))
                exitStatus = buf.readUInt32AsInt();
            else if ("exit-signal".equals(req)) {
                exitSignal = Signal.fromString(buf.readString());
                wasCoreDumped = buf.readBoolean(); // core dumped
                exitErrMsg = buf.readString();
                sendClose();
            } else
                super.handleRequest(req, buf);
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
    }

    @Override
    public void reqX11Forwarding(String authProto, String authCookie, int screen)
            throws ConnectionException, TransportException {
        sendChannelRequest(
                "x11-req",
                true,
                new Buffer.PlainBuffer()
                        .putBoolean(false)
                        .putString(authProto)
                        .putString(authCookie)
                        .putUInt32(screen)
        ).await(conn.getTimeout(), TimeUnit.SECONDS);
    }

    @Override
    public void setEnvVar(String name, String value)
            throws ConnectionException, TransportException {
        sendChannelRequest("env", true, new Buffer.PlainBuffer().putString(name).putString(value))
                .await(conn.getTimeout(), TimeUnit.SECONDS);
    }

    @Override
    public void signal(Signal sig)
            throws TransportException {
        sendChannelRequest("signal", false, new Buffer.PlainBuffer().putString(sig.toString()));
    }

    @Override
    public Shell startShell()
            throws ConnectionException, TransportException {
        checkReuse();
        sendChannelRequest("shell", true, null).await(conn.getTimeout(), TimeUnit.SECONDS);
        usedUp = true;
        return this;
    }

    @Override
    public Subsystem startSubsystem(String name)
            throws ConnectionException, TransportException {
        checkReuse();
        log.info("Will request `{}` subsystem", name);
        sendChannelRequest("subsystem", true, new Buffer.PlainBuffer().putString(name))
                .await(conn.getTimeout(), TimeUnit.SECONDS);
        usedUp = true;
        return this;
    }

    @Override
    public Boolean getExitWasCoreDumped() {
        return wasCoreDumped;
    }

    @Override
    protected void closeAllStreams() {
        IOUtils.closeQuietly(err);
        super.closeAllStreams();
    }

    @Override
    protected void eofInputStreams() {
        err.eof(); // also close the stderr stream
        super.eofInputStreams();
    }

    @Override
    protected void gotExtendedData(SSHPacket buf)
            throws ConnectionException, TransportException {
        try {
            final int dataTypeCode = buf.readUInt32AsInt();
            if (dataTypeCode == 1)
                receiveInto(err, buf);
            else
                throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR,
                                              "Bad extended data type = " + dataTypeCode);
        } catch (Buffer.BufferException be) {
            throw new ConnectionException(be);
        }
    }

    @Override
    public void notifyError(SSHException error) {
        err.notifyError(error);
        super.notifyError(error);
    }

    private void checkReuse() {
        if (usedUp)
            throw new SSHRuntimeException("This session channel is all used up");
    }

}
