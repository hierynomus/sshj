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
 */
package net.schmizz.sshj.xfer.scp;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import net.schmizz.sshj.xfer.FileTransferUtil;
import net.schmizz.sshj.xfer.ModeSetter;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

/** Support for uploading files over a connected link using SCP. */
public final class SCPDownloadClient
        extends SCPEngine {

    private final ModeSetter modeSetter;

    private boolean recursive = true;

    SCPDownloadClient(SessionFactory host, ModeSetter modeSetter) {
        super(host);
        this.modeSetter = modeSetter;
    }

    /** Download a file from {@code sourcePath} on the connected host to {@code targetPath} locally. */
    @Override
    public synchronized int copy(String sourcePath, String targetPath)
            throws IOException {
        return super.copy(sourcePath, targetPath);
    }

    public boolean getRecursive() {
        return recursive;
    }

    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
    }

    @Override
    void startCopy(String sourcePath, String targetPath)
            throws IOException {
        init(sourcePath);

        signal("Start status OK");

        String msg = readMessage(true);
        do
            process(null, msg, new File(targetPath));
        while ((msg = readMessage(false)) != null);
    }

    private void init(String source)
            throws SSHException {
        List<Arg> args = new LinkedList<Arg>();
        args.add(Arg.SOURCE);
        args.add(Arg.QUIET);
        if (recursive)
            args.add(Arg.RECURSIVE);
        if (modeSetter.preservesTimes())
            args.add(Arg.PRESERVE_TIMES);
        execSCPWith(args, source);
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

    private void prepare(File f, int perms, String tMsg)
            throws IOException {
        modeSetter.setPermissions(f, perms);

        if (tMsg != null && modeSetter.preservesTimes()) {
            String[] tMsgParts = tokenize(tMsg, 4); // e.g. T<mtime> 0 <atime> 0
            modeSetter.setLastModifiedTime(f, parseLong(tMsgParts[0].substring(1), "last modified time"));
            modeSetter.setLastAccessedTime(f, parseLong(tMsgParts[2], "last access time"));
        }
    }

    private boolean process(String bufferedTMsg, String msg, File f)
            throws IOException {
        if (msg.length() < 1)
            throw new SCPException("Could not parse message `" + msg + "`");

        switch (msg.charAt(0)) {

            case 'T':
                signal("ACK: T");
                process(msg, readMessage(true), f);
                break;

            case 'C':
                processFile(msg, bufferedTMsg, f);
                break;

            case 'D':
                processDirectory(msg, bufferedTMsg, f);
                break;

            case 'E':
                return true;

            case (char) 1:
                addWarning(msg.substring(1));
                break;

            case (char) 2:
                throw new SCPException("Remote SCP command returned error: " + msg.substring(1));

            default:
                String err = "Unrecognized message: `" + msg + "`";
                sendMessage((char) 2 + err);
                throw new SCPException(err);
        }

        return false;
    }

    private void processDirectory(String dMsg, String tMsg, File f)
            throws IOException {
        String[] dMsgParts = tokenize(dMsg, 3); // e.g. D0755 0 <dirname>

        long length = parseLong(dMsgParts[1], "dir length");
        if (length != 0)
            throw new IOException("Remote SCP command sent strange directory length: " + length);

        f = FileTransferUtil.getTargetDirectory(f, dMsgParts[2]);
        prepare(f, parsePermissions(dMsgParts[0]), tMsg);

        signal("ACK: D");

        do {
        } while (!process(null, readMessage(), f));

        signal("ACK: E");
    }

    private void processFile(String cMsg, String tMsg, File f)
            throws IOException {
        String[] cMsgParts = tokenize(cMsg, 3);

        long length = parseLong(cMsgParts[1], "length");

        f = FileTransferUtil.getTargetFile(f, cMsgParts[2]);
        prepare(f, parsePermissions(cMsgParts[0]), tMsg);

        signal("Remote can start transfer");
        final FileOutputStream fos = new FileOutputStream(f);
        try {
            transfer(scp.getInputStream(), fos, scp.getLocalMaxPacketSize(), length);
        } finally {
            IOUtils.closeQuietly(fos);
        }
        check("Remote agrees transfer done");
        signal("Transfer done");
    }

    private String[] tokenize(String msg, int numPartsExpected)
            throws IOException {
        String[] parts = msg.split(" ");
        if (parts.length != numPartsExpected)
            throw new IOException("Could not parse message received from remote SCP: " + msg);
        return parts;
    }

}