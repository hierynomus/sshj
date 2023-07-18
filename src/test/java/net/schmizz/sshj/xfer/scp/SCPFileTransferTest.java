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

import com.hierynomus.sshj.test.SshServerExtension;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SCPFileTransferTest {

    public static final String DEFAULT_FILE_NAME = "my_file.txt";
    Path targetDir;
    Path sourceFile;
    Path targetFile;
    SSHClient sshClient;

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @TempDir
    public File tempFolder;

    @BeforeEach
    public void init() throws IOException {
        sourceFile = Files.createFile(tempFolder.toPath().resolve(DEFAULT_FILE_NAME));
        FileUtil.writeToFile(sourceFile.toFile(), "This is my file");
        targetDir = Files.createDirectory(tempFolder.toPath().resolve("folder"));
        targetFile = targetDir.resolve(DEFAULT_FILE_NAME);
        sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
    }

    @AfterEach
    public void cleanup() {
        if (Files.exists(targetFile)) {
            try {
                Files.delete(targetFile);
            } catch (IOException ioe) {
                // ok
            }
        }
    }

    @Test
    public void shouldSCPUploadFile() throws IOException {
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer();
        assertFalse(Files.exists(targetFile));
        assertTrue(Files.exists(targetDir));
        scpFileTransfer.upload(sourceFile.toAbsolutePath().toString(), targetDir.toAbsolutePath().toString());
        assertTrue(Files.exists(targetFile));
    }

    @Test
    public void shouldSCPUploadFileWithBandwidthLimit() throws IOException {
        // Limit upload transfer at 2Mo/s
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer().bandwidthLimit(16000);
        assertFalse(Files.exists(targetFile));
        scpFileTransfer.upload(sourceFile.toAbsolutePath().toString(), targetDir.toAbsolutePath().toString());
        assertTrue(Files.exists(targetFile));
    }

    @Test
    public void shouldSCPDownloadFile() throws IOException {
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer();
        assertFalse(Files.exists(targetFile));
        scpFileTransfer.download(sourceFile.toAbsolutePath().toString(), targetDir.toAbsolutePath().toString());
        assertTrue(Files.exists(targetFile));
    }

    @Test
    public void shouldSCPDownloadFileWithBandwidthLimit() throws IOException {
        // Limit download transfer at 128Ko/s
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer().bandwidthLimit(1024);
        assertFalse(Files.exists(targetFile));
        scpFileTransfer.download(sourceFile.toAbsolutePath().toString(), targetDir.toAbsolutePath().toString());
        assertTrue(Files.exists(targetFile));
    }

    @Test
    public void shouldSCPDownloadFileWithoutPathEscaping() throws IOException {
        SCPFileTransfer scpFileTransfer = sshClient.newSCPFileTransfer();
        assertFalse(Files.exists(targetFile));
        Path file = tempFolder.toPath().resolve("new file.txt");
        FileUtil.writeToFile(file.toFile(), "Some content");
        scpFileTransfer.download(tempFolder.toPath().toAbsolutePath() + "/new file.txt", targetFile.toAbsolutePath().toString());
        assertTrue(Files.exists(targetFile));
        assertThat(FileUtil.readFromFile(targetFile.toFile()), CoreMatchers.containsString("Some content"));
    }
}
