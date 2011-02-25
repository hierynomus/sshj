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

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import net.schmizz.sshj.xfer.LocalFile;
import net.schmizz.sshj.xfer.ModeGetter;
import net.schmizz.sshj.xfer.TransferListener;

/** Support for uploading files over a connected link using SCP. */
public final class SCPUploadClient
        extends SCPEngine {

    private final ModeGetter modeGetter;

    private FileFilter fileFilter;

    SCPUploadClient(SessionFactory host, TransferListener listener, ModeGetter modeGetter) {
        super(host, listener);
        this.modeGetter = modeGetter;
    }

    /** Upload a file from {@code sourcePath} locally to {@code targetPath} on the remote host. */
    @Override
    public synchronized int copy(String sourcePath, String targetPath)
            throws IOException {
        return super.copy(sourcePath, targetPath);
    }

    /** Upload a local file from {@code localFile} to {@code targetPath} on the remote host. */
    public synchronized int copy(LocalFile sourceFile, String remotePath) 
		throws IOException {
		cleanSlate();
	    try {
	        startCopy(sourceFile, remotePath);
	    } finally {
	        exit();
	    }
	    return exitStatus;
    }

    public void setFileFilter(FileFilter fileFilter) {
        this.fileFilter = fileFilter;
    }

    @Override
    protected synchronized void startCopy(String sourcePath, String targetPath)
            throws IOException {
        init(targetPath);
        check("Start status OK");
        process(new File(sourcePath));
    }

	protected synchronized void startCopy(LocalFile sourceFile, String targetPath)
			throws IOException {
		init(targetPath);
        check("Start status OK");
        process(sourceFile);
	}
	
    private File[] getChildren(File f)
            throws IOException {
        File[] files = fileFilter == null ? f.listFiles() : f.listFiles(fileFilter);
        if (files == null)
            throw new IOException("Error listing files in directory: " + f);
        return files;
    }

    private void init(String target)
            throws SSHException {
        List<Arg> args = new LinkedList<Arg>();
        args.add(Arg.SINK);
        args.add(Arg.RECURSIVE);
        if (modeGetter.preservesTimes())
            args.add(Arg.PRESERVE_TIMES);
        execSCPWith(args, target);
    }

    private void process(File f)
            throws IOException {
        if (f.isDirectory()) {
            listener.startedDir(f.getName());
            sendDirectory(f);
            listener.finishedDir();
        } else if (f.isFile()) {
            listener.startedFile(f.getName(), f.length());
            sendFile(f);
            listener.finishedFile();
        } else
            throw new IOException(f + " is not a regular file or directory");
    }
    
    private void process(LocalFile f)
	    throws IOException {
		if (f.isDirectory()) {
		    listener.startedDir(f.getName());
		    sendDirectory(f);
		    listener.finishedDir();
		} else if (f.isFile()) {
		    listener.startedFile(f.getName(), f.length());
		    sendFile(f);
		    listener.finishedFile();
		} else
		    throw new IOException(f + " is not a regular file or directory");
	}

    private void sendDirectory(File f)
            throws IOException {
        preserveTimeIfPossible(f);
        sendMessage("D0" + getPermString(f) + " 0 " + f.getName());
        for (File child : getChildren(f))
            process(child);
        sendMessage("E");
    }

    private void sendDirectory(LocalFile f)
		    throws IOException {
		preserveTimeIfPossible(f);
		sendMessage("D0" + getPermString(f) + " 0 " + f.getName());
		for (LocalFile child : f.getChildren())
		    process(child);
		sendMessage("E");
	}
    
    private void sendFile(File f)
            throws IOException {
        preserveTimeIfPossible(f);
        final InputStream src = new FileInputStream(f);
        try {
            sendMessage("C0" + getPermString(f) + " " + f.length() + " " + f.getName());
            transfer(src, scp.getOutputStream(), scp.getRemoteMaxPacketSize(), f.length());
            signal("Transfer done");
            check("Remote agrees transfer done");
        } finally {
            IOUtils.closeQuietly(src);
        }
    }
    
    private void sendFile(LocalFile f)
		    throws IOException {
		preserveTimeIfPossible(f);
		final InputStream src = f.stream();
		try {
		    sendMessage("C0" + getPermString(f) + " " + f.length() + " " + f.getName());
		    transfer(src, scp.getOutputStream(), scp.getRemoteMaxPacketSize(), f.length());
		    signal("Transfer done");
		    check("Remote agrees transfer done");
		} finally {
		    IOUtils.closeQuietly(src);
		}
	}

    private void preserveTimeIfPossible(File f)
            throws IOException {
        if (modeGetter.preservesTimes())
            sendMessage("T" + modeGetter.getLastModifiedTime(f) + " 0 " + modeGetter.getLastAccessTime(f) + " 0");
    }
    
    private void preserveTimeIfPossible(LocalFile f)
		    throws IOException {
		if (modeGetter.preservesTimes())
		    sendMessage("T" + modeGetter.getLastModifiedTime(f) + " 0 " + modeGetter.getLastAccessTime(f) + " 0");
	}

    private String getPermString(File f)
            throws IOException {
        return Integer.toOctalString(modeGetter.getPermissions(f) & 07777);
    }
    
    private String getPermString(LocalFile f)
    		throws IOException {
    	return Integer.toOctalString(modeGetter.getPermissions(f) & 07777);
    }
}
