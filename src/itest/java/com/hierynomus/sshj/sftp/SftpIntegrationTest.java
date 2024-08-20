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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.SshdContainer;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.FileAttributes;
import net.schmizz.sshj.sftp.SFTPClient;

@Testcontainers
public class SftpIntegrationTest {
    @Container
    private static SshdContainer sshd = new SshdContainer();

    @Test
    public void shouldCheckFileExistsForNonExistingFile_GH894() throws Throwable {
        try (SSHClient client = sshd.getConnectedClient()) {
            client.authPublickey("sshj", "src/test/resources/id_rsa");
            try (SFTPClient sftp = client.newSFTPClient()) {
                String file = "/home/sshj/i_do_not_exist.txt";
                FileAttributes exists = sftp.statExistence(file);
                assertNull(exists);
            }
        }
    }
}
