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

import com.hierynomus.sshj.IntegrationBaseSpec
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts
import spock.lang.Unroll

import java.nio.file.Files
import java.util.stream.Collectors

/**
 * This is a brief test for verifying connection to a server using keys with certificates.
 *
 * Also, take a look at the unit test {@link net.schmizz.sshj.transport.verification.KeyWithCertificateUnitSpec}.
 */
class KeyWithCertificateSpec extends IntegrationBaseSpec {

    @Unroll
    def "authorising with a signed public key #keyName"() {
        given:
        def client = getConnectedClient()

        when:
        client.authPublickey(USERNAME, "src/itest/resources/keyfiles/certificates/$keyName")

        then:
        client.authenticated

        where:
        keyName << [
                "id_ecdsa_256_pem_signed_by_ecdsa",
                "id_ecdsa_256_rfc4716_signed_by_ecdsa",
                "id_ecdsa_256_pem_signed_by_ed25519",
                "id_ecdsa_256_rfc4716_signed_by_ed25519",
                "id_ecdsa_256_pem_signed_by_rsa",
                "id_ecdsa_256_rfc4716_signed_by_rsa",
                "id_ecdsa_384_pem_signed_by_ecdsa",
                "id_ecdsa_384_rfc4716_signed_by_ecdsa",
                "id_ecdsa_384_pem_signed_by_ed25519",
                "id_ecdsa_384_rfc4716_signed_by_ed25519",
                "id_ecdsa_384_pem_signed_by_rsa",
                "id_ecdsa_384_rfc4716_signed_by_rsa",
                "id_ecdsa_521_pem_signed_by_ecdsa",
                "id_ecdsa_521_rfc4716_signed_by_ecdsa",
                "id_ecdsa_521_pem_signed_by_ed25519",
                "id_ecdsa_521_rfc4716_signed_by_ed25519",
                "id_ecdsa_521_pem_signed_by_rsa",
                "id_ecdsa_521_rfc4716_signed_by_rsa",
                "id_rsa_2048_pem_signed_by_ecdsa",
                "id_rsa_2048_rfc4716_signed_by_ecdsa",
                "id_rsa_2048_pem_signed_by_ed25519",
                "id_rsa_2048_rfc4716_signed_by_ed25519",
                "id_rsa_2048_pem_signed_by_rsa",
                "id_rsa_2048_rfc4716_signed_by_rsa",
                "id_ed25519_384_rfc4716_signed_by_ecdsa",
                "id_ed25519_384_rfc4716_signed_by_ed25519",
                "id_ed25519_384_rfc4716_signed_by_rsa",
        ]
    }

    @Unroll
    def "accepting a signed host public key with type #hostKeyAlgo"() {
        given:
        File knownHosts = Files.createTempFile("known_hosts", "").toFile()
        knownHosts.deleteOnExit()

        and:
        File caPubKey = new File("src/itest/resources/keyfiles/certificates/CA_rsa.pem.pub")
        String knownHostsFileContents = "" +
                "@cert-authority $SERVER_IP ${caPubKey.text}" +
                "\n@cert-authority [$SERVER_IP]:$DOCKER_PORT ${caPubKey.text}"
        knownHosts.write(knownHostsFileContents)

        and:
        def config = new DefaultConfig()
        config.keyAlgorithms = config.keyAlgorithms.stream()
                .filter { it.name == hostKeyAlgo }
                .collect(Collectors.toList())
        SSHClient sshClient = new SSHClient(config)
        sshClient.addHostKeyVerifier(new OpenSSHKnownHosts(knownHosts))
        sshClient.connect(SERVER_IP, DOCKER_PORT)

        when:
        sshClient.authPassword("sshj", "ultrapassword")

        then:
        sshClient.authenticated

        and:
        knownHosts.getText() == knownHostsFileContents

        where:
        hostKeyAlgo << [
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                "ssh-ed25519-cert-v01@openssh.com",
                "ssh-rsa-cert-v01@openssh.com",
        ]
    }
}
