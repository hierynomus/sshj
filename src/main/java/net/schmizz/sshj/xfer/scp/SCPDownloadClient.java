/*
 * Copyright 2010-2012 sshj contributors, Cyril Ledru
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
import net.schmizz.sshj.xfer.LocalDestFile;
import net.schmizz.sshj.xfer.TransferListener;
import net.schmizz.sshj.xfer.scp.SCPEngine.Arg;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/** Support for uploading files over a connected link using SCP. */
public final class SCPDownloadClient {

    private boolean recursiveMode = true;

    private final SCPEngine engine;

    SCPDownloadClient(SCPEngine engine) {
        this.engine = engine;
    }

    /** Download a file from {@code sourcePath} on the connected host to {@code targetPath} locally. */
    public synchronized int copy(String sourcePath, LocalDestFile targetFile)
            throws IOException {
        engine.cleanSlate();
        try {
            startCopy(sourcePath, targetFile);
        } finally {
            engine.exit();
        }
        return engine.getExitStatus();
    }

    public boolean getRecursiveMode() {
        return recursiveMode;
    }

    public void setRecursiveMode(boolean recursive) {
        this.recursiveMode = recursive;
    }

    void startCopy(String sourcePath, LocalDestFile targetFile)
            throws IOException {
        List<Arg> args = new LinkedList<Arg>();
        args.add(Arg.SOURCE);
        args.add(Arg.QUIET);
        args.add(Arg.PRESERVE_TIMES);
        if (recursiveMode)
            args.add(Arg.RECURSIVE);
        engine.execSCPWith(args, sourcePath);

        engine.signal("Start status OK");

        String msg = engine.readMessage();
        do
            process(engine.getTransferListener(), null, msg, targetFile);
        while (!(msg = engine.readMessage()).isEmpty());
    }

    private long parseLong(String longString, String valType)
            throws SCPException {
        try {
            return Long.parseLong(longString);
        } catch (NumberFormatException nfe) {
            throw new SCPException("Could not parse " + valType + " from `" + longString + "`", nfe);
        }
    }

    /* e.g. "C0644" -> 0644; "D0755" -> 0755 */

    private int parsePermissions(String cmd)
            throws SCPException {
        if (cmd.length() != 5)
            throw new SCPException("Could not parse permissions from `" + cmd + "`");
        return Integer.parseInt(cmd.substring(1), 8);
    }

    private boolean process(TransferListener listener, String bufferedTMsg, String msg, LocalDestFile f)
            throws IOException {
        if (msg.length() < 1)
            throw new SCPException("Could not parse message `" + msg + "`");

        switch (msg.charAt(0)) {

            case 'T':
                engine.signal("ACK: T");
                process(listener, msg, engine.readMessage(), f);
                break;

            case 'C':
                processFile(listener, msg, bufferedTMsg, f);
                break;

            case 'D':
                processDirectory(listener, msg, bufferedTMsg, f);
                break;

            case 'E':
                return true;

            case (char) 1:
            case (char) 2:
                throw new SCPException("Remote SCP command returned error: " + msg.substring(1));

            default:
                final String err = "Unrecognized message: `" + msg + "`";
                engine.sendMessage((char) 2 + err);
                throw new SCPException(err);
        }

        return false;
    }

    private void processDirectory(TransferListener listener, String dMsg, String tMsg, LocalDestFile f)
            throws IOException {
        final List<String> dMsgParts = tokenize(dMsg, 3, true); // D<perms> 0 <dirname>
        final long length = parseLong(dMsgParts.get(1), "dir length");
        final String dirname = dMsgParts.get(2);
        if (length != 0)
            throw new IOException("Remote SCP command sent strange directory length: " + length);

        final TransferListener dirListener = listener.directory(dirname);
        {
            f = f.getTargetDirectory(dirname);
            engine.signal("ACK: D");
            do {
            } while (!process(dirListener, null, engine.readMessage(), f));
            setAttributes(f, parsePermissions(dMsgParts.get(0)), tMsg);
            engine.signal("ACK: E");
        }
    }

    private void processFile(TransferListener listener, String cMsg, String tMsg, LocalDestFile f)
            throws IOException {
        final List<String> cMsgParts = tokenize(cMsg, 3, true); // C<perms> <size> <filename>
        final long length = parseLong(cMsgParts.get(1), "length");
        final String filename = cMsgParts.get(2);
        {
            f = f.getTargetFile(filename);
            engine.signal("Remote can start transfer");
            final OutputStream dest = f.getOutputStream();
            try {
                engine.transferFromRemote(listener.file(filename, length), dest, length);
            } finally {
                IOUtils.closeQuietly(dest);
            }
            engine.check("Remote agrees transfer done");
            setAttributes(f, parsePermissions(cMsgParts.get(0)), tMsg);
            engine.signal("Transfer done");
        }
    }

    private void setAttributes(LocalDestFile f, int perms, String tMsg)
            throws IOException {
        f.setPermissions(perms);
        if (tMsg != null) {
            List<String> tMsgParts = tokenize(tMsg, 4, false); // e.g. T<mtime> 0 <atime> 0
            f.setLastModifiedTime(parseLong(tMsgParts.get(0).substring(1), "last modified time"));
            f.setLastAccessedTime(parseLong(tMsgParts.get(2), "last access time"));
        }
    }

    private static List<String> tokenize(String msg, int totalParts, boolean consolidateTail)
            throws IOException {
        List<String> parts = Arrays.asList(msg.split(" "));
        if (parts.size() < totalParts ||
                (!consolidateTail && parts.size() != totalParts))
            throw new IOException("Could not parse message received from remote SCP: " + msg);

        if (consolidateTail && totalParts < parts.size()) {
            final StringBuilder sb = new StringBuilder(parts.get(totalParts - 1));
            for (int i = totalParts; i < parts.size(); i++) {
                sb.append(" ").append(parts.get(i));
            }
            parts = new ArrayList<String>(parts.subList(0, totalParts - 1));
            parts.add(sb.toString());
        }

        return parts;
    }

}