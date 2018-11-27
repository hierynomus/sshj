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

import com.hierynomus.sshj.signature.SignatureEdDSA
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.signature.SignatureECDSA
import net.schmizz.sshj.transport.TransportException
import net.schmizz.sshj.userauth.UserAuthException
import spock.lang.Unroll

class IntegrationSpec extends IntegrationBaseSpec {

    @Unroll
    def "should accept correct key for #signatureName"() {
        given:
        def config = new DefaultConfig()
        config.setSignatureFactories(signatureFactory)
        SSHClient sshClient = new SSHClient(config)
        sshClient.addHostKeyVerifier(fingerprint) // test-containers/ssh_host_ecdsa_key's fingerprint

        when:
        sshClient.connect(SERVER_IP, DOCKER_PORT)

        then:
        sshClient.isConnected()

        where:
        signatureFactory << [new SignatureECDSA.Factory256(), new SignatureEdDSA.Factory()]
        fingerprint << ["d3:6a:a9:52:05:ab:b5:48:dd:73:60:18:0c:3a:f0:a3", "dc:68:38:ce:fc:6f:2c:d6:6d:6b:34:eb:5c:f0:41:6a"]
        signatureName = signatureFactory.getName()
    }

    def "should decline wrong key"() throws IOException {
        given:
        SSHClient sshClient = new SSHClient(new DefaultConfig())
        sshClient.addHostKeyVerifier("d4:6a:a9:52:05:ab:b5:48:dd:73:60:18:0c:3a:f0:a3")

        when:
        sshClient.connect(SERVER_IP, DOCKER_PORT)

        then:
        thrown(TransportException.class)
    }

    def "should authenticate"() {
        given:
        SSHClient client = getConnectedClient()

        when:
        client.authPublickey(USERNAME, KEYFILE)

        then:
        client.isAuthenticated()
    }

   def "should not authenticate with wrong key"() {
        given:
        SSHClient client = getConnectedClient()

        when:
        client.authPublickey("sshj", "src/test/resources/id_dsa")

        then:
        thrown(UserAuthException.class)
        !client.isAuthenticated()
    }
}
