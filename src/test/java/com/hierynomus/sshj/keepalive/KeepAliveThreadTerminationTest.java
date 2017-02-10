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
package com.hierynomus.sshj.keepalive;

import com.hierynomus.sshj.test.KnownFailingTests;
import com.hierynomus.sshj.test.SlowTests;
import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.keepalive.KeepAliveProvider;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.UserAuthException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;

import static org.junit.Assert.fail;

public class KeepAliveThreadTerminationTest {

    @Rule
    public SshFixture fixture = new SshFixture();

    @Test
    @Category({SlowTests.class, KnownFailingTests.class})
    public void shouldCorrectlyTerminateThreadOnDisconnect() throws IOException, InterruptedException {
        DefaultConfig defaultConfig = new DefaultConfig();
        defaultConfig.setKeepAliveProvider(KeepAliveProvider.KEEP_ALIVE);
        for (int i = 0; i < 10; i++) {
            SSHClient sshClient = fixture.setupClient(defaultConfig);
            fixture.connectClient(sshClient);
            sshClient.getConnection().getKeepAlive().setKeepAliveInterval(1);
            try {
                sshClient.authPassword("bad", "credentials");
                fail("Should not auth.");
            } catch (UserAuthException e) {
                // OK
            }
            fixture.stopClient();
            Thread.sleep(2000);
        }

        ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();
        for (long l : threadMXBean.getAllThreadIds()) {
            ThreadInfo threadInfo = threadMXBean.getThreadInfo(l);
            if (threadInfo.getThreadName().equals("keep-alive") && threadInfo.getThreadState() != Thread.State.TERMINATED) {
                fail("Found alive keep-alive thread in state " + threadInfo.getThreadState());
            }
        }
    }
}
