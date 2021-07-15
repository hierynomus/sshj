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

import net.schmizz.sshj.common.LoggerFactory;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static net.schmizz.sshj.sftp.PathHelper.DEFAULT_PATH_SEPARATOR;
import static org.mockito.Mockito.*;

public class SFTPClientTest {
    private final SFTPEngine sftpEngine = mock(SFTPEngine.class);

    @Before
    public void setPathHelper() throws Exception {
        PathHelper helper = new PathHelper(new PathHelper.Canonicalizer() {
            /**
             * Very basic, it does not try to canonicalize relative bits in the middle of a path.
             */
            @Override
            public String canonicalize(String path)
                    throws IOException {
                if ("".equals(path) || ".".equals(path) || "./".equals(path))
                    return "/home/me";
                if ("..".equals(path) || "../".equals(path))
                    return "/home";
                return path;
            }
        }, DEFAULT_PATH_SEPARATOR);
        when(sftpEngine.getPathHelper()).thenReturn(helper);
        when(sftpEngine.stat("/")).thenReturn(new FileAttributes.Builder().withType(FileMode.Type.DIRECTORY).build());
        when(sftpEngine.getLoggerFactory()).thenReturn(LoggerFactory.DEFAULT);
    }

    @Before
    public void setRemoteWorkingDirectory() throws IOException {
        FileAttributes isADirectory = new FileAttributes.Builder().withType(FileMode.Type.DIRECTORY).build();
        when(sftpEngine.stat("/workingdirectory")).thenReturn(isADirectory);
    }

    @Test
    public void doesNotTryToCreateDirectoryTwiceWhenPathHasTrailingSeparator() throws Exception {
        SFTPClient client = new SFTPClient(sftpEngine);
        try {
            client.mkdirs("/folder/directory/");
            verify(sftpEngine, times(1)).makeDir("/folder/directory");
        } finally {
            client.close();
        }
    }
}
