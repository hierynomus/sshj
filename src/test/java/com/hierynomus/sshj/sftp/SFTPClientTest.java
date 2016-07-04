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
package com.hierynomus.sshj.sftp;

import com.hierynomus.sshj.test.SshFixture;
import com.hierynomus.sshj.test.util.FileUtil;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.SFTPClient;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public class SFTPClientTest {

    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void shouldNotThrowExceptionOnCloseBeforeDisconnect() throws IOException {
        File file = temp.newFile("source.txt");
        FileUtil.writeToFile(file, "This is the source");

        doUpload(file, temp.newFile("dest.txt"));

    }

    @Test
    public void shouldUploadContentsToDestIfExistsAndSameNameAsSource() throws IOException {
        File srcDir = temp.newFolder("toto");
        File destDir = temp.newFolder("dest", "toto");
        FileUtil.writeToFile(new File(srcDir, "toto.txt"), "Toto file");

        doUpload(srcDir, destDir);

        assertThat("dest/toto exists", destDir.exists());
        assertThat("dest/toto/toto not exists", !new File(destDir, "toto").exists());
        assertThat("dest/toto/toto.txt exists", new File(destDir, "toto.txt").exists());
    }

    @Test
    public void shouldUploadIntoDestIfExistsAndDifferentNameAsSource() throws IOException {
        File srcDir = temp.newFolder("toto");
        File destDir = temp.newFolder("dest");
        FileUtil.writeToFile(new File(srcDir, "toto.txt"), "Toto file");

        doUpload(srcDir, destDir);

        assertThat("dest/toto exists", destDir.exists());
        assertThat("dest/toto/toto.txt exists", new File(destDir, "toto/toto.txt").exists());
    }

    @Test
    public void shouldNotMergeSameNameSubDirs() throws IOException {
        File toto = temp.newFolder("toto");
        File tutu = mkdir(toto, "tutu");
        File toto2 = mkdir(toto, "toto");
        File dest = temp.newFolder("dest");
        FileUtil.writeToFile(new File(toto, "toto.txt"), "Toto file");
        FileUtil.writeToFile(new File(tutu, "tototutu.txt"), "Toto/Tutu file");
        FileUtil.writeToFile(new File(toto2, "totototo.txt"), "Toto/Toto file");

        doUpload(toto, dest);

        assertThat("toto root should exist", new File(dest, "toto").exists());
        assertThat("toto/toto.txt should exist", new File(dest, "toto/toto.txt").exists());
        assertThat("toto/tutu should exist", new File(dest, "toto/tutu").exists());
        assertThat("toto/tutu/tototutu.txt should exist", new File(dest, "toto/tutu/tototutu.txt").exists());
        assertThat("toto/toto should exist", new File(dest, "toto/toto").exists());
        assertThat("toto/toto/totototo.txt should exist", new File(dest, "toto/toto/totototo.txt").exists());
        assertThat("toto/totototo.txt should not exist", !new File(dest, "totototo.txt").exists());
    }

    private void doUpload(File src, File dest) throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
        try {
            try (SFTPClient sftpClient = sshClient.newSFTPClient()) {
                sftpClient.put(src.getPath(), dest.getPath());
            }
        } finally {
            sshClient.disconnect();
        }
    }

    private File mkdir(File parent, String name) {
        File file = new File(parent, name);
        file.mkdir();
        return file;
    }
}
