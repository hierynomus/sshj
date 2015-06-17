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
}
