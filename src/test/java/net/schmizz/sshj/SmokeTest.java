/*
 * Copyright 2010, 2011 sshj contributors
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

import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.util.BasicFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertTrue;

/* Kinda basic right now */
public class SmokeTest {

    private final BasicFixture fixture = new BasicFixture();

    @Before
    public void setUp()
            throws IOException {
        fixture.init(false);
    }

    @After
    public void tearDown()
            throws IOException, InterruptedException {
        fixture.done();
    }

    @Test
    public void connected()
            throws IOException {
        assertTrue(fixture.getClient().isConnected());
    }

    @Test
    public void authenticated() throws UserAuthException, TransportException {
        fixture.dummyAuth();
        assertTrue(fixture.getClient().isAuthenticated());
    }

}