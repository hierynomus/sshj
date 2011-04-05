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

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.xfer.LocalFile;
import net.schmizz.sshj.xfer.ModeGetter;
import net.schmizz.sshj.xfer.scp.SCPEngine.Arg;

/** Support for uploading files over a connected link using SCP. */
public final class SCPUploadClient {

    private final ModeGetter modeGetter;

    private SCPEngine engine;

    SCPUploadClient(SCPEngine engine, ModeGetter modeGetter) {
        this.engine = engine;
        this.modeGetter = modeGetter;
    }

    /** Upload a local file from {@code localFile} to {@code targetPath} on the remote host. */
    public synchronized int copy(LocalFile sourceFile, String remotePath) 
		throws IOException {
		engine.cleanSlate();
	    try {
	        startCopy(sourceFile, remotePath);
	    } finally {
	    	engine.exit();
	    }
	    return engine.getExitStatus();
    }

    private synchronized void startCopy(LocalFile sourceFile, String targetPath)
			throws IOException {
		init(targetPath);
		engine.check("Start status OK");
        process(sourceFile);
	}
	
    private void init(String target)
            throws SSHException {
        List<Arg> args = new LinkedList<Arg>();
        args.add(Arg.SINK);
        args.add(Arg.RECURSIVE);
        if (modeGetter.preservesTimes())
            args.add(Arg.PRESERVE_TIMES);
        engine.execSCPWith(args, target);
    }

    private void process(LocalFile f)
	    throws IOException {
		if (f.isDirectory()) {
			engine.startedDir(f);
		    sendDirectory(f);
		    engine.finishedDir();
		} else if (f.isFile()) {
			engine.startedFile(f);
		    sendFile(f);
		    engine.finishedFile();
		} else
		    throw new IOException(f + " is not a regular file or directory");
	}

	private void sendDirectory(LocalFile f)
		    throws IOException {
		preserveTimeIfPossible(f);
		engine.sendMessage("D0" + getPermString(f) + " 0 " + f.getName());
		for (LocalFile child : f.getChildren())
		    process(child);
		engine.sendMessage("E");
	}
    
    private void sendFile(LocalFile f)
		    throws IOException {
		preserveTimeIfPossible(f);
		final InputStream src = f.stream();
		try {
			engine.sendMessage("C0" + getPermString(f) + " " + f.length() + " " + f.getName());
			engine.transfertToRemote(f, src);
			engine.signal("Transfer done");
			engine.check("Remote agrees transfer done");
		} finally {
		    IOUtils.closeQuietly(src);
		}
	}

    private void preserveTimeIfPossible(LocalFile f)
		    throws IOException {
		if (modeGetter.preservesTimes())
			engine.sendMessage("T" + modeGetter.getLastModifiedTime(f) + " 0 " + modeGetter.getLastAccessTime(f) + " 0");
	}

    private String getPermString(LocalFile f)
    		throws IOException {
    	return Integer.toOctalString(modeGetter.getPermissions(f) & 07777);
    }
}
