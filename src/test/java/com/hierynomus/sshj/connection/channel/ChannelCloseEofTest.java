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
package com.hierynomus.sshj.connection.channel;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.connection.channel.direct.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;

import static org.hamcrest.MatcherAssert.assertThat;

public class ChannelCloseEofTest {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    @Test
    public void shouldCorrectlyHandleSessionChannelEof() throws IOException, InterruptedException {
        fixture.setupConnectedDefaultClient().authPassword("jeroen", "jeroen");
        Session session = fixture.getClient().startSession();
        session.allocateDefaultPTY();
        session.close();
        Thread.sleep(1000);
        assertThat("Should still be connected", fixture.getClient().isConnected());
    }

}
