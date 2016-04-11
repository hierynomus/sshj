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
import net.schmizz.sshj.connection.channel.direct.Session;
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder;
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class IntegrationTest {

    @Test @Ignore // Should only be enabled for testing against VM
    public void shouldConnect() throws IOException, InterruptedException {
        SSHClient sshClient = new SSHClient(new DefaultConfig());
        sshClient.addHostKeyVerifier(new PromiscuousVerifier());
        sshClient.connect("172.16.37.129");
        sshClient.authPassword("jeroen", "jeroen");
        assertThat("Is connected", sshClient.isAuthenticated());
        sshClient.getRemotePortForwarder().bind(
                // where the server should listen
                new RemotePortForwarder.Forward("0.0.0.0", 8080),
                // what we do with incoming connections that are forwarded to us
                new SocketForwardingConnectListener(new InetSocketAddress("localhost", 8000)));
        new CountDownLatch(1).await();

    }
}
