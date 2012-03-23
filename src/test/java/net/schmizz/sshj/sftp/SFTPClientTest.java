package net.schmizz.sshj.sftp;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static net.schmizz.sshj.sftp.PathHelper.DEFAULT_PATH_SEPARATOR;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SFTPClientTest {
    private final SFTPEngine sftpEngine = mock(SFTPEngine.class);
    private final SFTPClient client = new SFTPClient(sftpEngine);

    @Before
    public void setPathHelper() throws Exception {
        PathHelper helper = new PathHelper(sftpEngine, DEFAULT_PATH_SEPARATOR);
        when(sftpEngine.getPathHelper()).thenReturn(helper);
    }

    @Before
    public void setRemoteWorkingDirectory() throws IOException {
        when(sftpEngine.canonicalize(".")).thenReturn("/workingdirectory");
        FileAttributes isADirectory = new FileAttributes.Builder().withType(FileMode.Type.DIRECTORY).build();
        when(sftpEngine.stat("/workingdirectory")).thenReturn(isADirectory);
    }

    @Test
    public void doesNotTryToCreateDirectoryTwiceWhenPathHasTrailingSeparator() throws Exception {
        client.mkdirs("/folder/directory/");
        verify(sftpEngine, times(1)).makeDir("/folder/directory");
    }
}