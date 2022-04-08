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

import com.hierynomus.sshj.test.SshFixture;
import com.hierynomus.sshj.test.util.FileUtil;
import java.io.File;
import java.io.IOException;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.xfer.TransferListener;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 *
 * @author Brent Tyler
 */
public class SFTPFileTransferTest {
    
    public static final String TARGET_FILE_NAME = "target.txt";
    
    File targetDir;
    File targetFile;
    File sourceFile;
    
    File partialFile;
    
    SSHClient sshClient;
    SFTPFileTransfer xfer;
    ByteCounter listener;
    
    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Before
    public void init() throws IOException {
        targetDir   = tempFolder.newFolder();
        targetFile  = new File(targetDir, TARGET_FILE_NAME);
        sourceFile  = new File("src/test/resources/files/test_file_full.txt");
        
        partialFile = new File("src/test/resources/files/test_file_partial.txt");
        
        sshClient   = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
        xfer = sshClient.newSFTPClient().getFileTransfer();
        xfer.setTransferListener(listener = new ByteCounter());
    }
    
    @After
    public void cleanup() {
        if (targetFile.exists()) {
            targetFile.delete();
        }
        
        if (targetDir.exists()) {
            targetDir.delete();
        }
    }
    
    private void performDownload(boolean resume) throws IOException {
        assertTrue(listener.getBytesTransferred() == 0);
        
        long expectedBytes = 0;
        
        // Using the resume param this way to call the different entry points into the FileTransfer interface
        if (resume) {
            expectedBytes = sourceFile.length() - targetFile.length(); // only the difference between what is there and what should be
            xfer.download(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath(), true);
        } else {
            expectedBytes = sourceFile.length(); // the entire source file should be transferred
            xfer.download(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath());
        }
        
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        assertTrue(listener.getBytesTransferred() == expectedBytes);
    }
    
    private void performUpload(boolean resume) throws IOException {
        assertTrue(listener.getBytesTransferred() == 0);
        
        long expectedBytes = 0;
        
        // Using the resume param this way to call the different entry points into the FileTransfer interface
        if (resume) {
            expectedBytes = sourceFile.length() - targetFile.length(); // only the difference between what is there and what should be
            xfer.upload(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath(), true);
        } else {
            expectedBytes = sourceFile.length(); // the entire source file should be transferred
            xfer.upload(sourceFile.getAbsolutePath(), targetFile.getAbsolutePath());
        }
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        assertTrue(listener.getBytesTransferred() == expectedBytes);
    }
    
    @Test
    public void testDownload() throws IOException {
        performDownload(false);
    }
    
    @Test
    public void testDownloadResumePartial() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(partialFile));
        assertFalse(FileUtil.compareFileContents(sourceFile, targetFile));
        performDownload(true);
    }
    
    @Test
    public void testDownloadResumeNothing() throws IOException {
        assertFalse(targetFile.exists());
        performDownload(true);
    }
    
    @Test
    public void testDownloadResumePreviouslyCompleted() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(sourceFile));
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        performDownload(true);
    }
    
    @Test
    public void testUpload() throws IOException {
        performUpload(false);
    }
    
    @Test
    public void testUploadResumePartial() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(partialFile));
        assertFalse(FileUtil.compareFileContents(sourceFile, targetFile));
        performUpload(true);
    }
    
    @Test
    public void testUploadResumeNothing() throws IOException {
        assertFalse(targetFile.exists());
        performUpload(true);
    }
    
    @Test
    public void testUploadResumePreviouslyCompleted() throws IOException {
        FileUtil.writeToFile(targetFile, FileUtil.readFromFile(sourceFile));
        assertTrue(FileUtil.compareFileContents(sourceFile, targetFile));
        performUpload(true);
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
