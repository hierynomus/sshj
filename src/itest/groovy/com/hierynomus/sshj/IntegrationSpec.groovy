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

import com.hierynomus.sshj.key.KeyAlgorithms
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.TransportException
import net.schmizz.sshj.userauth.UserAuthException
import spock.lang.Unroll

class IntegrationSpec extends IntegrationBaseSpec {

    @Unroll
    def "should accept correct key for #signatureName"() {
        given:
        def config = new DefaultConfig()
        config.setKeyAlgorithms(Collections.singletonList(signatureFactory))
        SSHClient sshClient = new SSHClient(config)
        sshClient.addHostKeyVerifier(fingerprint) // test-containers/ssh_host_ecdsa_key's fingerprint

        when:
        sshClient.connect(SERVER_IP, DOCKER_PORT)

        then:
        sshClient.isConnected()

        where:
        signatureFactory << [KeyAlgorithms.ECDSASHANistp256(), KeyAlgorithms.EdDSA25519()]
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

    @Unroll
    def "should authenticate with key #key"() {
        given:
        SSHClient client = getConnectedClient()

        when:
        def keyProvider = passphrase != null ? client.loadKeys("src/itest/resources/keyfiles/$key", passphrase) : client.loadKeys("src/itest/resources/keyfiles/$key")
        client.authPublickey(USERNAME, keyProvider)

        then:
        client.isAuthenticated()

        where:
        key | passphrase
//        "id_ecdsa_nistp256" | null // TODO: Need to improve PKCS8 key support.
        "id_ecdsa_opensshv1" | null
        "id_ed25519_opensshv1" | null
        "id_ed25519_opensshv1_aes256cbc.pem" | "foobar"
        "id_ed25519_opensshv1_protected" | "sshjtest"
        "id_rsa" | null
        "id_rsa_opensshv1" | null
        "id_ecdsa_nistp384_opensshv1" | null
        "id_ecdsa_nistp521_opensshv1" | null
    }

   def "should not authenticate with wrong key"() {
        given:
        SSHClient client = getConnectedClient()

        when:
        client.authPublickey("sshj", "src/itest/resources/keyfiles/id_unknown_key")

        then:
        thrown(UserAuthException.class)
        !client.isAuthenticated()
    }
}
