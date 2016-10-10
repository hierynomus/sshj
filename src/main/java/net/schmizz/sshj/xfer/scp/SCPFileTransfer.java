/*
 * Copyright (C)2009 - SSHJ Contributors
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

import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import net.schmizz.sshj.xfer.*;

import java.io.IOException;

public class SCPFileTransfer
        extends AbstractFileTransfer
        implements FileTransfer {

    /** Default bandwidth limit for SCP transfer in kilobit/s (-1 means unlimited) */
    private static final int DEFAULT_BANDWIDTH_LIMIT = -1;

    private final SessionFactory sessionFactory;
    private int bandwidthLimit;

    public SCPFileTransfer(SessionFactory sessionFactory, LoggerFactory loggerFactory) {
	super(loggerFactory);
        this.sessionFactory = sessionFactory;
        this.bandwidthLimit = DEFAULT_BANDWIDTH_LIMIT;
    }

    public SCPDownloadClient newSCPDownloadClient() {
        return new SCPDownloadClient(newSCPEngine(), bandwidthLimit);
    }

    public SCPUploadClient newSCPUploadClient() {
        return new SCPUploadClient(newSCPEngine(), bandwidthLimit);
    }

    private SCPEngine newSCPEngine() {
        return new SCPEngine(sessionFactory, getTransferListener(), loggerFactory);
    }

    @Override
    public void upload(String localPath, String remotePath)
            throws IOException {
        newSCPUploadClient().copy(new FileSystemFile(localPath), remotePath);
    }

    @Override
    public void download(String remotePath, String localPath)
            throws IOException {
        download(remotePath, new FileSystemFile(localPath));
    }

    @Override
    public void download(String remotePath, LocalDestFile localFile)
            throws IOException {
        newSCPDownloadClient().copy(remotePath, localFile);
    }

    @Override
    public void upload(LocalSourceFile localFile, String remotePath)
            throws IOException {
        newSCPUploadClient().copy(localFile, remotePath);
    }

    public SCPFileTransfer bandwidthLimit(int limit) {
        if (limit > 0) {
            this.bandwidthLimit = limit;
        }
        return this;
    }
}
