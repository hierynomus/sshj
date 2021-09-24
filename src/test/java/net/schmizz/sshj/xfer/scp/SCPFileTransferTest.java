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

import com.hierynomus.sshj.test.SshFixture;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import org.hamcrest.CoreMatchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;

public class SCPFileTransferTest {

    public static final String DEFAULT_FILE_NAME = "my_file.txt";
    File targetDir;
    File sourceFile;
    File targetFile;
    SSHClient sshClient;

    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Before
    public void init() throws IOException {
        sourceFile = tempFolder.newFile(DEFAULT_FILE_NAME);
        FileUtil.writeToFile(sourceFile, "This is my file");
        targetDir = tempFolder.newFolder();
        targetFile = new File(targetDir, DEFAULT_FILE_NAME);
        sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
    }

    @After
    public void cleanup() {
        if (targetFile.exists()) {
            targetFile.delete();
        }
    }

    @Test
    public void shouldSCPUploadFile() throws IOException {
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer();
        assertFalse(targetFile.exists());
        assertTrue(targetDir.exists());
        scpFileTransfer.upload(sourceFile.getAbsolutePath(), targetDir.getAbsolutePath());
        assertTrue(targetFile.exists());
    }

    @Test
    public void shouldSCPUploadFileWithBandwidthLimit() throws IOException {
        // Limit upload transfer at 2Mo/s
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer().bandwidthLimit(16000);
        assertFalse(targetFile.exists());
        scpFileTransfer.upload(sourceFile.getAbsolutePath(), targetDir.getAbsolutePath());
        assertTrue(targetFile.exists());
    }

    @Test
    public void shouldSCPDownloadFile() throws IOException {
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer();
        assertFalse(targetFile.exists());
        scpFileTransfer.download(sourceFile.getAbsolutePath(), targetDir.getAbsolutePath());
        assertTrue(targetFile.exists());
    }

    @Test
    public void shouldSCPDownloadFileWithBandwidthLimit() throws IOException {
        // Limit download transfer at 128Ko/s
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer().bandwidthLimit(1024);
        assertFalse(targetFile.exists());
        scpFileTransfer.download(sourceFile.getAbsolutePath(), targetDir.getAbsolutePath());
        assertTrue(targetFile.exists());
    }

    @Test
    public void shouldSCPDownloadFileWithoutPathEscaping() throws IOException {
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer();
        assertFalse(targetFile.exists());
        File file = tempFolder.newFile("new file.txt");
        FileUtil.writeToFile(file, "Some content");
        scpFileTransfer.download(tempFolder.getRoot().getAbsolutePath() + "/new file.txt", targetFile.getAbsolutePath());
        assertTrue(targetFile.exists());
        assertThat(FileUtil.readFromFile(targetFile), CoreMatchers.containsString("Some content"));
    }
}
