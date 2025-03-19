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

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.SshdContainer;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.OpenMode;
import net.schmizz.sshj.sftp.RemoteFile;
import net.schmizz.sshj.sftp.SFTPClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@Testcontainers
public class FileWriteTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer();

    @Test
    public void shouldAppendToFile_GH390() throws Throwable {
        try (SSHClient client = sshd.getConnectedClient()) {
            client.authPublickey("sshj", "src/test/resources/id_rsa");
            try (SFTPClient sftp = client.newSFTPClient()) {
                String file = "/home/sshj/test.txt";
                byte[] initialText = "This is the initial text.\n".getBytes(StandardCharsets.UTF_16);
                byte[] appendText = "And here's the appended text.\n".getBytes(StandardCharsets.UTF_16);

                try (RemoteFile initial = sftp.open(file, EnumSet.of(OpenMode.WRITE, OpenMode.CREAT))) {
                    initial.write(0, initialText, 0, initialText.length);
                }

                try (RemoteFile read = sftp.open(file, EnumSet.of(OpenMode.READ))) {
                    byte[] readBytes = new byte[initialText.length];
                    read.read(0, readBytes, 0, readBytes.length);
                    assertThat(readBytes).isEqualTo(initialText);
                }

                try (RemoteFile initial = sftp.open(file, EnumSet.of(OpenMode.WRITE, OpenMode.APPEND))) {
                    initial.write(0, appendText, 0, appendText.length);
                }

                try (RemoteFile read = sftp.open(file, EnumSet.of(OpenMode.READ))) {
                    byte[] readBytes = new byte[initialText.length + appendText.length];
                    read.read(0, readBytes, 0, readBytes.length);

                    final byte[] expectedInitialText = new byte[initialText.length];
                    System.arraycopy(readBytes, 0, expectedInitialText, 0, expectedInitialText.length);
                    assertArrayEquals(expectedInitialText, initialText);

                    final byte[] expectedAppendText = new byte[appendText.length];
                    System.arraycopy(readBytes, initialText.length, expectedAppendText, 0, expectedAppendText.length);
                    assertArrayEquals(expectedAppendText, appendText);
                }
            }

        }
    }
}
