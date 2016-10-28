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
package com.hierynomus.sshj;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;
import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile;

import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public class IntegrationTest {

    @Test @Ignore // Should only be enabled for testing against VM
    public void shouldConnect() throws IOException {
        SSHClient sshClient = new SSHClient(new DefaultConfig());
        sshClient.addHostKeyVerifier(new OpenSSHKnownHosts(new File("/Users/ajvanerp/.ssh/known_hosts")));
        sshClient.connect("172.16.37.147");
//        OpenSSHKeyV1KeyFile openSSHKeyV1KeyFile = new OpenSSHKeyV1KeyFile();
//        openSSHKeyV1KeyFile.init(new File("/Users/ajvanerp/.ssh/id_ed25519"));
        sshClient.authPublickey("jeroen");
        assertThat("Is connected", sshClient.isAuthenticated());
    }
}
