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
package net.schmizz.sshj.connection.channel.direct;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.Connection;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.channel.ChannelInputStream;
import net.schmizz.sshj.transport.TransportException;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** {@link Session} implementation. */
public class
        SessionChannel
        extends AbstractDirectChannel
        implements Session, Session.Command, Session.Shell, Session.Subsystem {

    private final ChannelInputStream err = new ChannelInputStream(this, trans, lwin);

    private Integer exitStatus;

    private Signal exitSignal;
    private Boolean wasCoreDumped;
    private String exitErrMsg;

    private Boolean canDoFlowControl;

    public SessionChannel(Connection conn) {
        super(conn, "session");
    }

    public void allocateDefaultPTY()
            throws ConnectionException, TransportException {
        // TODO FIXME (maybe?): These modes were originally copied from what SSHD was doing;
        // and then the echo modes were set to 0 to better serve the PTY example.
        // Not sure what default PTY modes should be.
        final Map<PTYMode, Integer> modes = new HashMap<PTYMode, Integer>();
        modes.put(PTYMode.ISIG, 1);
        modes.put(PTYMode.ICANON, 1);
        modes.put(PTYMode.ECHO, 0);
        modes.put(PTYMode.ECHOE, 0);
        modes.put(PTYMode.ECHOK, 0);
        modes.put(PTYMode.ECHONL, 0);
        modes.put(PTYMode.NOFLSH, 0);
        allocatePTY("vt100", 0, 0, 0, 0, modes);
    }

    public void allocatePTY(String term, int cols, int rows, int width, int height, Map<PTYMode, Integer> modes)
            throws ConnectionException, TransportException {
        sendChannelRequest(
                "pty-req",
                true,
                new Buffer.PlainBuffer()
                        .putString(term)
                        .putInt(cols)
                        .putInt(rows)
                        .putInt(width)
                        .putInt(height)
                        .putBytes(PTYMode.encode(modes))
        ).await(conn.getTimeout(), TimeUnit.SECONDS);
    }

    public Boolean canDoFlowControl() {
        return canDoFlowControl;
    }

    public void changeWindowDimensions(int cols, int rows, int width, int height)
            throws TransportException {
        sendChannelRequest(
                "pty-req",
                false,
                new Buffer.PlainBuffer()
                        .putInt(cols)
                        .putInt(rows)
                        .putInt(width)
                        .putInt(height)
        );
    }

    public Command exec(String command)
            throws ConnectionException, TransportException {
        log.info("Will request to exec `{}`", command);
        sendChannelRequest("exec", true, new Buffer.PlainBuffer().putString(command))
                .await(conn.getTimeout(), TimeUnit.SECONDS);
        return this;
    }

    public String getErrorAsString()
            throws IOException {
        return StreamCopier.copyStreamToString(err);
    }

    public InputStream getErrorStream() {
        return err;
    }

    public String getExitErrorMessage() {
        return exitErrMsg;
    }

    public Signal getExitSignal() {
        return exitSignal;
    }

    public Integer getExitStatus() {
        return exitStatus;
    }

    public String getOutputAsString()
            throws IOException {
        return StreamCopier.copyStreamToString(getInputStream());
    }

    @Override
    public void handleRequest(String req, SSHPacket buf)
            throws ConnectionException, TransportException {
        if ("xon-xoff".equals(req))
            canDoFlowControl = buf.readBoolean();
        else if ("exit-status".equals(req))
            exitStatus = buf.readInt();
        else if ("exit-signal".equals(req)) {
            exitSignal = Signal.fromString(buf.readString());
            wasCoreDumped = buf.readBoolean(); // core dumped
            exitErrMsg = buf.readString();
            sendClose();
        } else
            super.handleRequest(req, buf);
    }

    public void reqX11Forwarding(String authProto, String authCookie, int screen)
            throws ConnectionException,
                   TransportException {
        sendChannelRequest(
                "x11-req",
                true,
                new Buffer.PlainBuffer()
                        .putBoolean(false)
                        .putString(authProto)
                        .putString(authCookie)
                        .putInt(screen)
        ).await(conn.getTimeout(), TimeUnit.SECONDS);
    }

    public void setEnvVar(String name, String value)
            throws ConnectionException, TransportException {
        sendChannelRequest("env", true, new Buffer.PlainBuffer().putString(name).putString(value))
                .await(conn.getTimeout(), TimeUnit.SECONDS);
    }

    public void signal(Signal sig)
            throws TransportException {
        sendChannelRequest("signal", false, new Buffer.PlainBuffer().putString(sig.toString()));
    }

    public Shell startShell()
            throws ConnectionException, TransportException {
        sendChannelRequest("shell", true, null).await(conn.getTimeout(), TimeUnit.SECONDS);
        return this;
    }

    public Subsystem startSubsystem(String name)
            throws ConnectionException, TransportException {
        log.info("Will request `{}` subsystem", name);
        sendChannelRequest("subsystem", true, new Buffer.PlainBuffer().putString(name))
                .await(conn.getTimeout(), TimeUnit.SECONDS);
        return this;
    }

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
    protected void gotExtendedData(int dataTypeCode, SSHPacket buf)
            throws ConnectionException, TransportException {
        if (dataTypeCode == 1)
            receiveInto(err, buf);
        else
            super.gotExtendedData(dataTypeCode, buf);
    }

}