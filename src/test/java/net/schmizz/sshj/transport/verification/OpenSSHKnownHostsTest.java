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
package net.schmizz.sshj.transport.verification;

import net.schmizz.sshj.util.KeyUtil;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class OpenSSHKnownHostsTest {

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    public File writeKnownHosts(String line)
            throws IOException {
        File known_hosts = temp.newFile("known_hosts");
        FileWriter fileWriter = new FileWriter(known_hosts);
        BufferedWriter writer = new BufferedWriter(fileWriter);
        writer.write(line);
        writer.write("\r\n");
        writer.flush();
        writer.close();
        return known_hosts;
    }

    @Test
    public void shouldAddCommentForEmptyLine()
            throws IOException {
        File file = writeKnownHosts("");
        OpenSSHKnownHosts openSSHKnownHosts = new OpenSSHKnownHosts(file);
        assertThat(openSSHKnownHosts.entries().size(), equalTo(1));
        assertThat(openSSHKnownHosts.entries().get(0), instanceOf(OpenSSHKnownHosts.CommentEntry.class));
    }

    @Test
    public void shouldAddCommentForCommentLine()
            throws IOException {
        File file = writeKnownHosts("# this is a comment");
        OpenSSHKnownHosts openSSHKnownHosts = new OpenSSHKnownHosts(file);
        assertThat(openSSHKnownHosts.entries().size(), equalTo(1));
        assertThat(openSSHKnownHosts.entries().get(0), instanceOf(OpenSSHKnownHosts.CommentEntry.class));
    }

    @Test
    public void testSchmizzEntry()
            throws IOException, GeneralSecurityException {
        OpenSSHKnownHosts kh = new OpenSSHKnownHosts(new File("src/test/resources/known_hosts"));
        final PublicKey key = KeyUtil
                .newRSAPublicKey(
                        "e8ff4797075a861db9d2319960a836b2746ada3da514955d2921f2c6a6c9895cbd557f604e43772b6303e3cab2ad82d83b21acdef4edb72524f9c2bef893335115acacfe2989bcbb2e978e4fedc8abc090363e205d975c1fdc35e55ba4daa4b5d5ab7a22c40f547a4a0fd1c683dfff10551c708ff8c34ea4e175cb9bf2313865308fa23601e5a610e2f76838be7ded3b4d3a2c49d2d40fa20db51d1cc8ab20d330bb0dadb88b1a12853f0ecb7c7632947b098dcf435a54566bcf92befd55e03ee2a57d17524cd3d59d6e800c66059067e5eb6edb81946b3286950748240ec9afa4389f9b62bc92f94ec0fba9e64d6dc2f455f816016a4c5f3d507382ed5d3365",
                        "23");

        assertTrue(kh.verify("schmizz.net", 22, key));
        assertTrue(kh.verify("69.163.155.180", 22, key));
        assertFalse(kh.verify("69.163.155.18", 22, key));
    }

    @Test
    public void testVerifyIndexError() throws Exception {
        final OpenSSHKnownHosts v = new OpenSSHKnownHosts(new File("src/test/resources/known_hosts.invalid"));
        assertTrue(v.entries().isEmpty());
    }
}
