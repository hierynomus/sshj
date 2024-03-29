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
package net.schmizz.sshj;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

/* Kinda basic right now */
public class SmokeTest {

    private final SshServerExtension fixture = new SshServerExtension();

    @BeforeEach
    public void setUp()
            throws IOException {
        fixture.start();
        fixture.setupConnectedDefaultClient();
    }

    @AfterEach
    public void tearDown()
            throws IOException, InterruptedException {
        fixture.stopClient();
        fixture.stopServer();
    }

    @Test
    public void connected()
            throws IOException {
        assertTrue(fixture.getClient().isConnected());
    }

    @Test
    public void authenticated()
            throws UserAuthException, TransportException {
        fixture.getClient().authPassword("dummy", "dummy");
        assertTrue(fixture.getClient().isAuthenticated());
    }

}
