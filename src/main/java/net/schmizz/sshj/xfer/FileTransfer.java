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
package net.schmizz.sshj.xfer;

import java.io.IOException;

public interface FileTransfer {

    /**
     * This is meant to delegate to {@link #upload(LocalSourceFile, String)} with the {@code localPath} wrapped as e.g.
     * a {@link FileSystemFile}.
     *
     * @param localPath
     * @param remotePath
     *
     * @throws IOException
     */
    void upload(String localPath, String remotePath)
            throws IOException;

    /**
     * This is meant to delegate to {@link #download(String, LocalDestFile)} with the {@code localPath} wrapped as e.g.
     * a {@link FileSystemFile}.
     *
     * @param localPath
     * @param remotePath
     *
     * @throws IOException
     */
    void download(String remotePath, String localPath)
            throws IOException;

    /**
     * Upload {@code localFile} to {@code remotePath}.
     *
     * @param localFile
     * @param remotePath
     *
     * @throws IOException
     */
    void upload(LocalSourceFile localFile, String remotePath)
            throws IOException;

    /**
     * Download {@code remotePath} to {@code localFile}.
     *
     * @param localFile
     * @param remotePath
     *
     * @throws IOException
     */
    void download(String remotePath, LocalDestFile localFile)
            throws IOException;

    TransferListener getTransferListener();

    void setTransferListener(TransferListener listener);

}
