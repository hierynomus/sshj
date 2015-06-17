package com.hierynomus.sshj.connection.channel.direct;

import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.Session;
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
        Session.Command exec = sshClient.startSession().exec("mkdir " + file.getPath() + " &");
        exec.join();
        assertThat("File should exist", file.exists());
        assertThat("File should be directory", file.isDirectory());
    }
}
