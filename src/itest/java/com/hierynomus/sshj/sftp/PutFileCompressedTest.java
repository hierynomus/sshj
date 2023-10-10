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

import com.hierynomus.sshj.SshdContainer;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.SFTPClient;
import net.schmizz.sshj.xfer.InMemorySourceFile;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

@Testcontainers
public class PutFileCompressedTest {

    private static class TestInMemorySourceFile extends InMemorySourceFile {

        private final String name;
        private final byte[] data;

        public TestInMemorySourceFile(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public long getLength() {
            return data.length;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return new ByteArrayInputStream(data);
        }

    }

    @Container
    private static SshdContainer sshd = new SshdContainer();

    @Test
    public void shouldPutCompressedFile_GH893() throws Throwable {
        try (SSHClient client = sshd.getConnectedClient()) {
            client.authPublickey("sshj", "src/test/resources/id_rsa");
            client.useCompression();
            try (SFTPClient sftp = client.newSFTPClient()) {
                String filename = "test.txt";
                // needs to be a larger file for bug taking effect
                byte[] content = new byte[5000];
                Random r = new Random(1);
                r.nextBytes(content);

                sftp.put(new TestInMemorySourceFile(filename,content), "/home/sshj/");
            }

        }
    }
}
