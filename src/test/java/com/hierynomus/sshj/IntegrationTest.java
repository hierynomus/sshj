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

import static org.hamcrest.MatcherAssert.assertThat;

import java.io.File;
import java.io.IOException;

import org.junit.Ignore;
import org.junit.Test;

import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;

public class IntegrationTest {

    @Test @Ignore // Should only be enabled for testing against VM
    public void shouldConnectVM() throws IOException {
        SSHClient sshClient = new SSHClient(new DefaultConfig());
        sshClient.addHostKeyVerifier(new OpenSSHKnownHosts(new File("/Users/ajvanerp/.ssh/known_hosts")));
        sshClient.connect("172.16.37.147");
        sshClient.authPublickey("jeroen");
        assertThat("Is connected", sshClient.isAuthenticated());
    }
    
    @Test // Should only be enabled for testing against VM
    public void shouldConnect() throws IOException {
        SSHClient sshClient = new SSHClient(new DefaultConfig());
        sshClient.addHostKeyVerifier("d3:6a:a9:52:05:ab:b5:48:dd:73:60:18:0c:3a:f0:a3"); // test-containers/ssh_host_ecdsa_key's fingerprint
        sshClient.connect("192.168.99.100", 2222);
        sshClient.authPublickey("sshj", "src/test/resources/id_rsa");
        assertThat("Is connected", sshClient.isAuthenticated());
    }
}
