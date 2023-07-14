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
import net.schmizz.sshj.Config
import net.schmizz.sshj.DefaultConfig
import org.testcontainers.images.builder.dockerfile.DockerfileBuilder
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.file.Paths

/**
 * Checks that SSHJ is able to work with OpenSSH 8.8, which removed ssh-rsa signature from the default setup.
 */
class RsaShaKeySignatureTest extends Specification {
    private static final Map<String, KeyAlgorithms.Factory> SSH_HOST_KEYS_AND_FACTORIES = [
        'ssh_host_ecdsa_256_key': KeyAlgorithms.ECDSASHANistp256(),
        'ssh_host_ecdsa_384_key': KeyAlgorithms.ECDSASHANistp384(),
        'ssh_host_ecdsa_521_key': KeyAlgorithms.ECDSASHANistp521(),
        'ssh_host_ed25519_384_key': KeyAlgorithms.EdDSA25519(),
        'ssh_host_rsa_2048_key': KeyAlgorithms.RSASHA512(),
    ]

    private static void dockerfileBuilder(DockerfileBuilder it, String hostKey, String pubkeyAcceptedAlgorithms) {
        it.from("archlinux:base")
        it.run('pacman -Sy --noconfirm core/openssh core/openssl' +
                ' && (' +
                '  V=$(echo $(/usr/sbin/sshd -h 2>&1) | grep -o \'OpenSSH_[0-9][0-9]*[.][0-9][0-9]*p[0-9]\');' +
                '  if [[ "$V" < OpenSSH_8.8p1 ]]; then' +
                '    echo $V is too old 1>&2;' +
                '    exit 1;' +
                '   fi' +
                ')' +
                ' && set -o pipefail ' +
                ' && useradd --create-home sshj' +
                ' && echo \"sshj:ultrapassword\" | chpasswd')
        it.add("authorized_keys", "/home/sshj/.ssh/")
        it.add(hostKey, '/etc/ssh/')
        it.run('chmod go-rwx /etc/ssh/ssh_host_*' +
                ' && chown -R sshj /home/sshj/.ssh' +
                ' && chmod -R go-rwx /home/sshj/.ssh')
        it.expose(22)

        def cmd = [
                '/usr/sbin/sshd',
                '-D',
                '-e',
                '-f', '/dev/null',
                '-o', "HostKey=/etc/ssh/$hostKey",
        ]
        if (pubkeyAcceptedAlgorithms != null) {
            cmd += ['-o', "PubkeyAcceptedAlgorithms=$pubkeyAcceptedAlgorithms"]
        }
        it.cmd(cmd as String[])
    }

    private static SshdContainer makeSshdContainer(String hostKey, String pubkeyAcceptedAlgorithms) {
        return new SshdContainer(new SshdContainer.DebugLoggingImageFromDockerfile()
                .withFileFromPath("authorized_keys", Paths.get("src/itest/docker-image/authorized_keys"))
                .withFileFromPath(hostKey, Paths.get("src/itest/docker-image/test-container/host_keys/$hostKey"))
                .withDockerfileFromBuilder {
                    dockerfileBuilder(it, hostKey, pubkeyAcceptedAlgorithms)
                })
    }

    @Unroll
    def "connect to a server with host key #hostKey that does not support ssh-rsa"() {
        given:
        SshdContainer sshd = makeSshdContainer(hostKey, "rsa-sha2-512,rsa-sha2-256,ssh-ed25519")
        sshd.start()

        and:
        Config config = new DefaultConfig()
        config.keyAlgorithms = [
                KeyAlgorithms.RSASHA512(),
                KeyAlgorithms.RSASHA256(),
                SSH_HOST_KEYS_AND_FACTORIES[hostKey],
        ]

        when:
        def sshClient = sshd.getConnectedClient(config)
        sshClient.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1")

        then:
        sshClient.isAuthenticated()

        cleanup:
        sshClient?.disconnect()
        sshd.stop()

        where:
        hostKey << SSH_HOST_KEYS_AND_FACTORIES.keySet()
    }

    @Unroll
    def "connect to a default server with host key #hostKey using a default config"() {
        given:
        SshdContainer sshd = makeSshdContainer(hostKey, null)
        sshd.start()

        when:
        def sshClient = sshd.getConnectedClient()
        sshClient.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1")

        then:
        sshClient.isAuthenticated()

        cleanup:
        sshClient?.disconnect()
        sshd.stop()

        where:
        hostKey << SSH_HOST_KEYS_AND_FACTORIES.keySet()
    }

    @Unroll
    def "connect to a server with host key #hostKey that supports only ssh-rsa"() {
        given:
        SshdContainer sshd = makeSshdContainer(hostKey, "ssh-rsa,ssh-ed25519")
        sshd.start()

        and:
        Config config = new DefaultConfig()
        config.keyAlgorithms = [
                KeyAlgorithms.SSHRSA(),
                SSH_HOST_KEYS_AND_FACTORIES[hostKey],
        ]

        when:
        def sshClient = sshd.getConnectedClient(config)
        sshClient.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1")

        then:
        sshClient.isAuthenticated()

        cleanup:
        sshClient.disconnect()
        sshd.stop()

        where:
        hostKey << SSH_HOST_KEYS_AND_FACTORIES.keySet()
    }
}
