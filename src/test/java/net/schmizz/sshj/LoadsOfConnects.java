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

import java.io.IOException;

public class LoadsOfConnects {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final SshFixture fixture = new SshFixture();

    @Test
    public void loadsOfConnects()
            throws IOException, InterruptedException {
        for (int i = 0; i < 1000; i++) {
            System.out.println("Try " + i);
            fixture.start();
            fixture.setupConnectedDefaultClient();
            fixture.stopClient();
            fixture.stopServer();
        }
    }

}