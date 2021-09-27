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

import com.hierynomus.sshj.test.SshFixture;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;

import static org.junit.Assert.fail;

public class LoadsOfConnects {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final SshFixture fixture = new SshFixture();

    @Test
    public void loadsOfConnects() {
        try {
            fixture.start();
            for (int i = 0; i < 1000; i++) {
                log.info("Try " + i);
                SSHClient client = fixture.setupConnectedDefaultClient();
                client.authPassword("test", "test");
                Session s = client.startSession();
                Session.Command c = s.exec("ls");
                IOUtils.readFully(c.getErrorStream());
                IOUtils.readFully(c.getInputStream());
                c.close();
                s.close();
                fixture.stopClient();
            }
        } catch (Exception e) {
            fail(e.getMessage());
        } finally {
            fixture.stopServer();
        }

    }

}
