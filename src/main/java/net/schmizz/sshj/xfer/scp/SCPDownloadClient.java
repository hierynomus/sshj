/*
 * Copyright 2010, 2011 sshj contributors, Cyril Ledru
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

import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.xfer.LocalFile;
import net.schmizz.sshj.xfer.scp.SCPEngine.Arg;

/** Support for uploading files over a connected link using SCP. */
public final class SCPDownloadClient {

    private boolean recursive = true;

	private SCPEngine engine;

    SCPDownloadClient(SCPEngine engine) {
        this.engine = engine;
    }

    /** Download a file from {@code sourcePath} on the connected host to {@code targetPath} locally. */
    public synchronized int copy(String sourcePath, LocalFile targetFile)
            throws IOException {
    	engine.cleanSlate();
        try {
            startCopy(sourcePath, targetFile);
        } finally {
        	engine.exit();
        }
        return engine.getExitStatus();
    }

    public boolean getRecursive() {
        return recursive;
    }

    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
    }

    void startCopy(String sourcePath, LocalFile targetFile)
            throws IOException {
        List<Arg> args = new LinkedList<Arg>();
        args.add(Arg.SOURCE);
        args.add(Arg.QUIET);
        if (recursive)
            args.add(Arg.RECURSIVE);
        if (targetFile.preservesTimes())
            args.add(Arg.PRESERVE_TIMES);
        engine.execSCPWith(args, sourcePath);

        engine.signal("Start status OK");

        String msg = engine.readMessage(true);
        do
            process(null, msg, targetFile);
        while ((msg = engine.readMessage(false)) != null);
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

    private boolean process(String bufferedTMsg, String msg, LocalFile f)
            throws IOException {
        if (msg.length() < 1)
            throw new SCPException("Could not parse message `" + msg + "`");

        switch (msg.charAt(0)) {

            case 'T':
            	engine.signal("ACK: T");
                process(msg, engine.readMessage(true), f);
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
            case (char) 2:
                throw new SCPException("Remote SCP command returned error: " + msg.substring(1));

            default:
                String err = "Unrecognized message: `" + msg + "`";
                engine.sendMessage((char) 2 + err);
                throw new SCPException(err);
        }

        return false;
    }

    private void processDirectory(String dMsg, String tMsg, LocalFile f)
            throws IOException {
        final String[] dMsgParts = tokenize(dMsg, 3); // D<perms> 0 <dirname>
        final long length = parseLong(dMsgParts[1], "dir length");
        final String dirname = dMsgParts[2];
        if (length != 0)
            throw new IOException("Remote SCP command sent strange directory length: " + length);
        engine.startedDir(dirname);
        {
            f = f.getTargetDirectory(dirname);
            engine.signal("ACK: D");
            do {
            } while (!process(null, engine.readMessage(), f));
            setAttributes(f, parsePermissions(dMsgParts[0]), tMsg);
            engine.signal("ACK: E");
        }
        engine.finishedDir();
    }

	private void processFile(String cMsg, String tMsg, LocalFile f)
            throws IOException {
        final String[] cMsgParts = tokenize(cMsg, 3); // C<perms> <size> <filename>
        final long length = parseLong(cMsgParts[1], "length");
        final String filename = cMsgParts[2];
        engine.startedFile(length, filename);
        {
            f = f.getTargetFile(filename);
            engine.signal("Remote can start transfer");
            final OutputStream os = f.getOutputStream();
            try {
            	engine.transferFromRemote(length, os);
            } finally {
                IOUtils.closeQuietly(os);
            }
            engine.check("Remote agrees transfer done");
            setAttributes(f, parsePermissions(cMsgParts[0]), tMsg);
            engine.signal("Transfer done");
        }
        engine.finishedFile();
    }

	private void setAttributes(LocalFile f, int perms, String tMsg)
            throws IOException {
        f.setPermissions(perms);
        if (tMsg != null && f.preservesTimes()) {
            String[] tMsgParts = tokenize(tMsg, 4); // e.g. T<mtime> 0 <atime> 0
            f.setLastModifiedTime(parseLong(tMsgParts[0].substring(1), "last modified time"));
            f.setLastAccessedTime(parseLong(tMsgParts[2], "last access time"));
        }
    }

    private String[] tokenize(String msg, int numPartsExpected)
            throws IOException {
        String[] parts = msg.split(" ");
        if (parts.length != numPartsExpected)
            throw new IOException("Could not parse message received from remote SCP: " + msg);
        return parts;
    }

}