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
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.ByteArrayUtils;
import net.schmizz.sshj.sftp.OpenMode;
import net.schmizz.sshj.sftp.RemoteFile;
import net.schmizz.sshj.sftp.SFTPEngine;
import net.schmizz.sshj.sftp.SFTPException;
import org.apache.sshd.common.util.io.IoUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.*;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Random;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class RemoteFileTest {
    @Rule
    public SshFixture fixture = new SshFixture();

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void shouldNotGoOutOfBoundsInReadAheadInputStream() throws IOException {
        SSHClient ssh = fixture.setupConnectedDefaultClient();
        ssh.authPassword("test", "test");
        SFTPEngine sftp = new SFTPEngine(ssh).init();

        RemoteFile rf;
        File file = temp.newFile("SftpReadAheadTest.bin");
        rf = sftp.open(file.getPath(), EnumSet.of(OpenMode.WRITE, OpenMode.CREAT));
        byte[] data = new byte[8192];
        new Random(53).nextBytes(data);
        data[3072] = 1;
        rf.write(0, data, 0, data.length);
        rf.close();

        assertThat("The file should exist", file.exists());

        rf = sftp.open(file.getPath());
        InputStream rs = rf.new ReadAheadRemoteFileInputStream(16 /*maxUnconfirmedReads*/);

        byte[] test = new byte[4097];
        int n = 0;

        while (n < 2048) {
            n += rs.read(test, n, 2048 - n);
        }

        while (n < 3072) {
            n += rs.read(test, n, 3072 - n);
        }

        assertThat("buffer overrun", test[3072] == 0);

        n += rs.read(test, n, test.length - n); // --> ArrayIndexOutOfBoundsException

        byte[] test2 = new byte[data.length];
        System.arraycopy(test, 0, test2, 0, test.length);

        while (n < data.length) {
            n += rs.read(test2, n, data.length - n);
        }

        assertThat("The written and received data should match", data, equalTo(test2));
    }

    @Test
    public void shouldNotReadAheadAfterLimitInputStream() throws IOException {
        SSHClient ssh = fixture.setupConnectedDefaultClient();
        ssh.authPassword("test", "test");
        SFTPEngine sftp = new SFTPEngine(ssh).init();

        RemoteFile rf;
        File file = temp.newFile("SftpReadAheadLimitTest.bin");
        rf = sftp.open(file.getPath(), EnumSet.of(OpenMode.WRITE, OpenMode.CREAT));
        byte[] data = new byte[8192];
        new Random(53).nextBytes(data);
        data[3072] = 1;
        rf.write(0, data, 0, data.length);
        rf.close();

        assertThat("The file should exist", file.exists());

        rf = sftp.open(file.getPath());
        InputStream rs = rf.new ReadAheadRemoteFileInputStream(16 /*maxUnconfirmedReads*/,0, 3072);

        byte[] test = new byte[4097];
        int n = 0;

        while (n < 2048) {
            n += rs.read(test, n, 2048 - n);
        }

        rf.close();

        while (n < 3072) {
            n += rs.read(test, n, 3072 - n);
        }

        assertThat("buffer overrun", test[3072] == 0);

        try {
            rs.read(test, n, test.length - n);
            fail("Content must not be buffered");
        } catch (SFTPException e){
            // expected
        }
    }

    @Test
    public void limitedReadAheadInputStream() throws IOException {
        SSHClient ssh = fixture.setupConnectedDefaultClient();
        ssh.authPassword("test", "test");
        SFTPEngine sftp = new SFTPEngine(ssh).init();

        RemoteFile rf;
        File file = temp.newFile("SftpReadAheadLimitedTest.bin");
        rf = sftp.open(file.getPath(), EnumSet.of(OpenMode.WRITE, OpenMode.CREAT));
        byte[] data = new byte[8192];
        new Random(53).nextBytes(data);
        data[3072] = 1;
        rf.write(0, data, 0, data.length);
        rf.close();

        assertThat("The file should exist", file.exists());

        rf = sftp.open(file.getPath());
        InputStream rs = rf.new ReadAheadRemoteFileInputStream(16 /*maxUnconfirmedReads*/,0, 3072);

        byte[] test = new byte[4097];
        int n = 0;

        while (n < 2048) {
            n += rs.read(test, n, 2048 - n);
        }

        while (n < 3072) {
            n += rs.read(test, n, 3072 - n);
        }

        assertThat("buffer overrun", test[3072] == 0);

        n += rs.read(test, n, test.length - n); // --> ArrayIndexOutOfBoundsException

        byte[] test2 = new byte[data.length];
        System.arraycopy(test, 0, test2, 0, test.length);

        while (n < data.length) {
            n += rs.read(test2, n, data.length - n);
        }

        assertThat("The written and received data should match", data, equalTo(test2));
    }

    @Test
    public void shouldReadCorrectlyWhenWrappedInBufferedStream_FullSizeBuffer() throws IOException {
        doTestShouldReadCorrectlyWhenWrappedInBufferedStream(1024 * 1024, 1024 * 1024);
    }

    @Test
    public void shouldReadCorrectlyWhenWrappedInBufferedStream_HalfSizeBuffer() throws IOException {
        doTestShouldReadCorrectlyWhenWrappedInBufferedStream(1024 * 1024, 512 * 1024);
    }

    @Test
    public void shouldReadCorrectlyWhenWrappedInBufferedStream_QuarterSizeBuffer() throws IOException {
        doTestShouldReadCorrectlyWhenWrappedInBufferedStream(1024 * 1024, 256 * 1024);
    }

    @Test
    public void shouldReadCorrectlyWhenWrappedInBufferedStream_SmallSizeBuffer() throws IOException {
        doTestShouldReadCorrectlyWhenWrappedInBufferedStream(1024 * 1024, 1024);
    }

    private void doTestShouldReadCorrectlyWhenWrappedInBufferedStream(int fileSize, int bufferSize) throws IOException {
        SSHClient ssh = fixture.setupConnectedDefaultClient();
        ssh.authPassword("test", "test");
        SFTPEngine sftp = new SFTPEngine(ssh).init();

        final byte[] expected = new byte[fileSize];
        new SecureRandom(new byte[] { 31 }).nextBytes(expected);

        File file = temp.newFile("shouldReadCorrectlyWhenWrappedInBufferedStream.bin");
        try (OutputStream fStream = new FileOutputStream(file)) {
            IoUtils.copy(new ByteArrayInputStream(expected), fStream);
        }

        RemoteFile rf = sftp.open(file.getPath());
        final byte[] actual;
        try (InputStream inputStream = new BufferedInputStream(
                rf.new ReadAheadRemoteFileInputStream(10),
                bufferSize)
        ) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            IoUtils.copy(inputStream, baos, expected.length);
            actual = baos.toByteArray();
        }

        assertEquals("The file should be fully read", expected.length, actual.length);
        assertThat("The file should be read correctly",
                ByteArrayUtils.equals(expected, 0, actual, 0, expected.length));
    }
}
