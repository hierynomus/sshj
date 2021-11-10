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
package com.hierynomus.sshj.signature

import com.hierynomus.sshj.SshdContainer
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.file.Files

/**
 * This is a brief test for verifying connection to a server using keys with certificates.
 *
 * Also, take a look at the unit test {@link net.schmizz.sshj.transport.verification.KeyWithCertificateUnitSpec}.
 */
class HostKeyWithCertificateSpec extends Specification {
    @Unroll
    def "accepting a signed host public key #hostKey"() {
        given:
        SshdContainer sshd = new SshdContainer.Builder()
            .withSshdConfig("""
                PasswordAuthentication yes
                HostKey /etc/ssh/$hostKey
                HostCertificate /etc/ssh/${hostKey}-cert.pub
                """.stripMargin())
            .build()
        sshd.start()

        and:
        File knownHosts = Files.createTempFile("known_hosts", "").toFile()
        knownHosts.deleteOnExit()

        and:
        File caPubKey = new File("src/itest/resources/keyfiles/certificates/CA_rsa.pem.pub")
        def address = "127.0.0.1"
        String knownHostsFileContents = "" +
                "@cert-authority ${ address} ${caPubKey.text}" +
                "\n@cert-authority [${address}]:${sshd.firstMappedPort} ${caPubKey.text}"
        knownHosts.write(knownHostsFileContents)

        and:
        SSHClient sshClient = new SSHClient(new DefaultConfig())
        sshClient.addHostKeyVerifier(new OpenSSHKnownHosts(knownHosts))
        sshClient.connect(address, sshd.firstMappedPort)

        when:
        sshClient.authPassword("sshj", "ultrapassword")

        then:
        sshClient.authenticated

        and:
        knownHosts.getText() == knownHostsFileContents

        cleanup:
        sshd.stop()

        where:
        hostKey << [
                "ssh_host_ecdsa_256_key",
                "ssh_host_ecdsa_384_key",
                "ssh_host_ecdsa_521_key",
                "ssh_host_ed25519_384_key",
                "ssh_host_rsa_2048_key",
        ]
    }
}
