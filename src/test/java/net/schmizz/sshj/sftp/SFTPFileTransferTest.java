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
package net.schmizz.sshj.sftp;

import com.hierynomus.sshj.test.SshServerExtension;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.xfer.TransferListener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SFTPFileTransferTest {

    public static final String TARGET_FILE_NAME = "target.txt";

    File targetDir;
    File targetFile;
    File sourceFile;

    File partialFile;

    SSHClient sshClient;
    SFTPFileTransfer xfer;
    ByteCounter listener;

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @TempDir
    public File tempFolder;

    @BeforeEach
    public void init() throws IOException {
        targetDir   = new File(tempFolder, "targetDir");
        assertTrue(targetDir.mkdir());
        targetFile  = new File(targetDir, TARGET_FILE_NAME);
        sourceFile  = new File("src/test/resources/files/test_file_full.txt");

        partialFile = new File("src/test/resources/files/test_file_partial.txt");

        sshClient   = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
        xfer = sshClient.newSFTPClient().getFileTransfer();
        xfer.setTransferListener(listener = new ByteCounter());
    }

    @AfterEach
    public void cleanup() {
        if (targetFile.exists()) {
            targetFile.delete();
        }

        if (targetDir.exists()) {
            targetDir.delete();
        }
    }

    private void performDownload(long byteOffset) throws IOException {
        assertTrue(listener.getBytesTransferred() == 0);

        long expectedBytes = 0;

        // Using the resume param this way to call the different entry points into the FileTransfer interface
        if (byteOffset > 0) {
            expectedBytes = sourceFile.length() - targetFile.length(); // only the difference between what is there and what should be
            xfer.download(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath(), byteOffset);
        } else {
            expectedBytes = sourceFile.length(); // the entire source file should be transferred
            xfer.download(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath());
        }

        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        assertTrue(listener.getBytesTransferred() == expectedBytes);
    }

    private void performUpload(long byteOffset) throws IOException {
        assertTrue(listener.getBytesTransferred() == 0);

        long expectedBytes = 0;

        // Using the resume param this way to call the different entry points into the FileTransfer interface
        if (byteOffset > 0) {
            expectedBytes = sourceFile.length() - targetFile.length(); // only the difference between what is there and what should be
            xfer.upload(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath(), byteOffset);
        } else {
            expectedBytes = sourceFile.length(); // the entire source file should be transferred
            xfer.upload(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath());
        }
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        assertTrue(listener.getBytesTransferred() == expectedBytes);
    }

    @Test
    public void testDownload() throws IOException {
        performDownload(0);
    }

    @Test
    public void testDownloadResumePartial() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(partialFile));
        assertFalse(FileUtil.compareFileContents(sourceFile, targetFile));
        performDownload(targetFile.length());
    }

    @Test
    public void testDownloadResumeNothing() throws IOException {
        assertFalse(targetFile.exists());
        performDownload(targetFile.length());
    }

    @Test
    public void testDownloadResumePreviouslyCompleted() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(sourceFile));
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        performDownload(targetFile.length());
    }

    @Test
    public void testUpload() throws IOException {
        performUpload(0);
    }

    @Test
    public void testUploadResumePartial() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(partialFile));
        assertFalse(FileUtil.compareFileContents(sourceFile, targetFile));
        performUpload(targetFile.length());
    }

    @Test
    public void testUploadResumeNothing() throws IOException {
        assertFalse(targetFile.exists());
        performUpload(targetFile.length());
    }

    @Test
    public void testUploadResumePreviouslyCompleted() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(sourceFile));
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        performUpload(targetFile.length());
    }

    public class ByteCounter implements TransferListener, StreamCopier.Listener {
        long bytesTransferred;

        public long getBytesTransferred() {
            return bytesTransferred;
        }

        @Override
        public TransferListener directory(String name) {
            return this;
        }

        @Override
        public StreamCopier.Listener file(String name, long size) {
            return this;
        }

        @Override
        public void reportProgress(long transferred) throws IOException {
            bytesTransferred = transferred;
        }
    }
}
