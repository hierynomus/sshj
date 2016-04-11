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
import net.schmizz.sshj.sftp.FileAttributes;
import net.schmizz.sshj.sftp.SFTPClient;
import org.hamcrest.CoreMatchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.DataPoint;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class SFTPClientTest {

    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void shouldNotThrowExceptionOnCloseBeforeDisconnect() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
        SFTPClient sftpClient = sshClient.newSFTPClient();
        File file = temp.newFile("source.txt");
        FileUtil.writeToFile(file, "This is the source");
        try {
            try {
                sftpClient.put(file.getPath(), temp.newFile("dest.txt").getPath());
             } finally {
                sftpClient.close();
            }
        } finally {
            sshClient.disconnect();
        }
    }

    @Test
    @DataPoint
    public void shouldNotCreateAbsoluteDirectoryWhenPathIsRelative() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("test", "test");
        SFTPClient sftpClient = sshClient.newSFTPClient();
        String foo = sftpClient.canonicalize("foo");
        String fooAbs = sftpClient.canonicalize("/foo");
        assertThat(sftpClient.statExistence("foo"), nullValue());
        sftpClient.mkdirs("foo");
        assertThat(sftpClient.statExistence("foo"), notNullValue());
        sftpClient.rmdir("foo");
        assertThat(sftpClient.statExistence("foo"), nullValue());
        sftpClient.close();
        sshClient.disconnect();
    }
}
