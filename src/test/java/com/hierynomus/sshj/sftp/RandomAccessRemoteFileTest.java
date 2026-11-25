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

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.OpenMode;
import net.schmizz.sshj.sftp.RandomAccessRemoteFile;
import net.schmizz.sshj.sftp.SFTPEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class RandomAccessRemoteFileTest {
    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @TempDir
    public File temp;

    private SFTPEngine sftp() throws IOException {
        SSHClient ssh = fixture.setupConnectedDefaultClient();
        ssh.authPassword("test", "test");
        return new SFTPEngine(ssh).init();
    }

    @Test
    public void shouldReadBytesAsUnsigned() throws IOException {
        File file = new File(temp, "bytes.bin");
        Files.write(file.toPath(), new byte[]{(byte) 0xff, 0, 0, 0, (byte) 0xc8});

        RandomAccessRemoteFile raf = new RandomAccessRemoteFile(sftp().open(file.getPath()));

        assertEquals(0xff, raf.read());
        assertEquals(200, raf.readInt());
    }

    @Test
    public void shouldReturnNullFromReadLineAtEndOfFile() throws IOException {
        File file = new File(temp, "lines.txt");
        Files.write(file.toPath(), "a\nb".getBytes(StandardCharsets.US_ASCII));

        RandomAccessRemoteFile raf = new RandomAccessRemoteFile(sftp().open(file.getPath()));

        assertEquals("a", raf.readLine());
        assertEquals("b", raf.readLine());
        assertNull(raf.readLine());
    }

    @Test
    public void shouldAdvanceFilePointerByLengthWhenWritingFromAnOffset() throws IOException {
        File file = new File(temp, "write.bin");
        RandomAccessRemoteFile raf = new RandomAccessRemoteFile(
                sftp().open(file.getPath(), EnumSet.of(OpenMode.WRITE, OpenMode.CREAT)));

        raf.write("xxabcd".getBytes(StandardCharsets.US_ASCII), 2, 4);
        raf.write('e');

        assertEquals(5, raf.getFilePointer());
        assertEquals("abcde", new String(Files.readAllBytes(file.toPath()), StandardCharsets.US_ASCII));
    }
}
