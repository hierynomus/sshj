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
package com.hierynomus.sshj.connection.channel.direct;

import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.sftp.SFTPClient;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public class CommandTest {

    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void shouldExecuteBackgroundCommand() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("jeroen", "jeroen");
        File file = new File(temp.getRoot(), "testdir");
        assertThat("File should not exist", !file.exists());
        // TODO figure out why this does not really execute in the background.
        Session.Command exec = sshClient.startSession().exec("mkdir " + file.getPath() + " &");
        exec.join();
        assertThat("File should exist", file.exists());
        assertThat("File should be directory", file.isDirectory());
        SFTPClient sftpClient = sshClient.newSFTPClient();
        if (sftpClient.statExistence("&") != null) {
            sftpClient.rmdir("&");
            // TODO fail here when this is fixed
        }
    }
}
