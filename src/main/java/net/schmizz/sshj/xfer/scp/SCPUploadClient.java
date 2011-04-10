/*
 * Copyright 2010, 2011 sshj contributors
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
import net.schmizz.sshj.xfer.LocalSourceFile;
import net.schmizz.sshj.xfer.scp.SCPEngine.Arg;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

/** Support for uploading files over a connected link using SCP. */
public final class SCPUploadClient {

    private final SCPEngine engine;

    SCPUploadClient(SCPEngine engine) {
        this.engine = engine;
    }

    /** Upload a local file from {@code localFile} to {@code targetPath} on the remote host. */
    public synchronized int copy(LocalSourceFile sourceFile, String remotePath)
            throws IOException {
        engine.cleanSlate();
        try {
            startCopy(sourceFile, remotePath);
        } finally {
            engine.exit();
        }
        return engine.getExitStatus();
    }

    private synchronized void startCopy(LocalSourceFile sourceFile, String targetPath)
            throws IOException {
        List<Arg> args = new LinkedList<Arg>();
        args.add(Arg.SINK);
        args.add(Arg.RECURSIVE);
        if (sourceFile.providesAtimeMtime())
            args.add(Arg.PRESERVE_TIMES);
        engine.execSCPWith(args, targetPath);
        engine.check("Start status OK");
        process(sourceFile);
    }

    private void process(LocalSourceFile f)
            throws IOException {
        if (f.isDirectory()) {
            engine.startedDir(f.getName());
            sendDirectory(f);
            engine.finishedDir();
        } else if (f.isFile()) {
            engine.startedFile(f.getName(), f.getLength());
            sendFile(f);
            engine.finishedFile();
        } else
            throw new IOException(f + " is not a regular file or directory");
    }

    private void sendDirectory(LocalSourceFile f)
            throws IOException {
        preserveTimeIfPossible(f);
        engine.sendMessage("D0" + getPermString(f) + " 0 " + f.getName());
        for (LocalSourceFile child : f.getChildren(null))
            process(child);
        engine.sendMessage("E");
    }

    private void sendFile(LocalSourceFile f)
            throws IOException {
        preserveTimeIfPossible(f);
        final InputStream src = f.getInputStream();
        try {
            engine.sendMessage("C0" + getPermString(f) + " " + f.getLength() + " " + f.getName());
            engine.transferToRemote(src, f.getLength());
            engine.signal("Transfer done");
            engine.check("Remote agrees transfer done");
        } finally {
            IOUtils.closeQuietly(src);
        }
    }

    private void preserveTimeIfPossible(LocalSourceFile f)
            throws IOException {
        if (f.providesAtimeMtime())
            engine.sendMessage("T" + f.getLastModifiedTime() + " 0 " + f.getLastAccessTime() + " 0");
    }

    private String getPermString(LocalSourceFile f)
            throws IOException {
        return Integer.toOctalString(f.getPermissions() & 07777);
    }

}
