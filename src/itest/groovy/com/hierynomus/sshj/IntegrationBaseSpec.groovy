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
package com.hierynomus.sshj

import net.schmizz.sshj.Config
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import spock.lang.Specification

class IntegrationBaseSpec extends Specification {
    protected static final int DOCKER_PORT = 2222
    protected static final String USERNAME = "sshj"
    protected static final String KEYFILE = "src/itest/resources/keyfiles/id_rsa"
    protected final static String SERVER_IP = System.getProperty("serverIP", "127.0.0.1")

    protected static SSHClient getConnectedClient(Config config) {
        SSHClient sshClient = new SSHClient(config)
        sshClient.addHostKeyVerifier(new PromiscuousVerifier())
        sshClient.connect(SERVER_IP, DOCKER_PORT)

        return sshClient
    }

    protected static SSHClient getConnectedClient() throws IOException {
        return getConnectedClient(new DefaultConfig())
    }

}
