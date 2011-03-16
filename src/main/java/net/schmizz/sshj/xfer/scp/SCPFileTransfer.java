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

import java.io.IOException;

import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import net.schmizz.sshj.xfer.AbstractFileTransfer;
import net.schmizz.sshj.xfer.FileSystemFile;
import net.schmizz.sshj.xfer.FileTransfer;
import net.schmizz.sshj.xfer.LocalFile;

public class SCPFileTransfer
        extends AbstractFileTransfer
        implements FileTransfer {

    private final SessionFactory sessionFactory;

    public SCPFileTransfer(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    public SCPDownloadClient newSCPDownloadClient() {
        return new SCPDownloadClient(getSCPEngine(), getModeSetter());
    }

    public SCPUploadClient newSCPUploadClient() {
        return new SCPUploadClient(getSCPEngine(), getModeGetter());
    }

    private SCPEngine getSCPEngine() {
    	return new SCPEngine(sessionFactory, getTransferListener());
    }

    @Override
    public void download(String remotePath, String localPath)
            throws IOException {
        newSCPDownloadClient().copy(remotePath, localPath);
    }

    @Override
    public void upload(String localPath, String remotePath)
            throws IOException {
        newSCPUploadClient().copy(new FileSystemFile(localPath), remotePath);
    }

    @Override
	public void upload(LocalFile localFile, String remotePath)
			throws IOException {
		newSCPUploadClient().copy(localFile, remotePath);
	}
}
