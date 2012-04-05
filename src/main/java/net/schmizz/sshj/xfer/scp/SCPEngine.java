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
package net.schmizz.sshj.xfer.scp;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.connection.channel.direct.Session.Command;
import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import net.schmizz.sshj.xfer.TransferListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/** @see <a href="http://blogs.sun.com/janp/entry/how_the_scp_protocol_works">SCP Protocol</a> */
class SCPEngine {

    static enum Arg {
        SOURCE('f'),
        SINK('t'),
        RECURSIVE('r'),
        VERBOSE('v'),
        PRESERVE_TIMES('p'),
        QUIET('q');

        private final char a;

        private Arg(char a) {
            this.a = a;
        }

        @Override
        public String toString() {
            return "-" + a;
        }
    }

    private static final String SCP_COMMAND = "scp";
    private static final char LF = '\n';

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final SessionFactory host;
    private final TransferListener listener;

    private Command scp;
    private int exitStatus;

    SCPEngine(SessionFactory host, TransferListener listener) {
        this.host = host;
        this.listener = listener;
    }

    public int getExitStatus() {
        return exitStatus;
    }

    void check(String what)
            throws IOException {
        int code = scp.getInputStream().read();
        switch (code) {
            case -1:
                String stderr = IOUtils.readFully(scp.getErrorStream()).toString();
                if (!stderr.isEmpty())
                    stderr = ". Additional info: `" + stderr + "`";
                throw new SCPException("EOF while expecting response to protocol message" + stderr);
            case 0: // OK
                log.debug(what);
                return;
            case 1: // Warning? not
            case 2:
                throw new SCPException("Remote SCP command had error: " + readMessage());
            default:
                throw new SCPException("Received unknown response code");
        }
    }

    void cleanSlate() {
        exitStatus = -1;
    }

    void execSCPWith(List<Arg> args, String path)
            throws SSHException {
        final StringBuilder cmd = new StringBuilder(SCP_COMMAND);
        for (Arg arg : args)
            cmd.append(" ").append(arg);
        cmd.append(" ");
        if (path == null || path.isEmpty())
            cmd.append(".");
        else
            cmd.append("'").append(path.replaceAll("'", "\\'")).append("'");
        scp = host.startSession().exec(cmd.toString());
    }

    void exit() {
        if (scp != null) {

            IOUtils.closeQuietly(scp);

            if (scp.getExitStatus() != null) {
                exitStatus = scp.getExitStatus();
                if (scp.getExitStatus() != 0)
                    log.warn("SCP exit status: {}", scp.getExitStatus());
            } else
                exitStatus = -1;

            if (scp.getExitSignal() != null)
                log.warn("SCP exit signal: {}", scp.getExitSignal());
        }

        scp = null;
    }

    String readMessage()
            throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int x;
        while ((x = scp.getInputStream().read()) != LF)
            if (x == -1) {
                if (baos.size() == 0)
                    return "";
                else
                    throw new IOException("EOF while reading message");
            } else
                baos.write(x);
        final String msg = baos.toString(IOUtils.UTF8.displayName());
        log.debug("Read message: `{}`", msg);
        return msg;
    }

    void sendMessage(String msg)
            throws IOException {
        log.debug("Sending message: {}", msg);
        scp.getOutputStream().write((msg + LF).getBytes(IOUtils.UTF8));
        scp.getOutputStream().flush();
        check("Message ACK received");
    }

    void signal(String what)
            throws IOException {
        log.debug("Signalling: {}", what);
        scp.getOutputStream().write(0);
        scp.getOutputStream().flush();
    }

    long transferToRemote(StreamCopier.Listener listener, InputStream src, long length)
            throws IOException {
        return new StreamCopier(src, scp.getOutputStream())
                .bufSize(scp.getRemoteMaxPacketSize()).length(length)
                .keepFlushing(false)
                .listener(listener)
                .copy();
    }

    long transferFromRemote(StreamCopier.Listener listener, OutputStream dest, long length)
            throws IOException {
        return new StreamCopier(scp.getInputStream(), dest)
                .bufSize(scp.getLocalMaxPacketSize()).length(length)
                .keepFlushing(false)
                .listener(listener)
                .copy();
    }

    TransferListener getTransferListener() {
        return listener;
    }

}
