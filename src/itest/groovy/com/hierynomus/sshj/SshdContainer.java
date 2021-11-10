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
package com.hierynomus.sshj;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.jetbrains.annotations.NotNull;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.dockerfile.DockerfileBuilder;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.concurrent.Future;

/**
 * A JUnit4 rule for launching a generic SSH server container.
 */
public class SshdContainer extends GenericContainer<SshdContainer> {
    @SuppressWarnings("unused")  // Used dynamically by Spock
    public SshdContainer() {
        this(new ImageFromDockerfile()
                .withDockerfileFromBuilder(SshdContainer::defaultDockerfileBuilder)
                .withFileFromPath(".", Paths.get("src/itest/docker-image")));
    }

    public SshdContainer(@NotNull Future<String> future) {
        super(future);
        withExposedPorts(22);
        setWaitStrategy(new SshServerWaitStrategy());
    }

    public static void defaultDockerfileBuilder(@NotNull DockerfileBuilder builder) {
        builder.from("sickp/alpine-sshd:7.5-r2");

        builder.add("authorized_keys", "/home/sshj/.ssh/authorized_keys");

        builder.add("test-container/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ecdsa_key");
        builder.add("test-container/ssh_host_ecdsa_key.pub", "/etc/ssh/ssh_host_ecdsa_key.pub");
        builder.add("test-container/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key");
        builder.add("test-container/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_ed25519_key.pub");
        builder.add("test-container/sshd_config", "/etc/ssh/sshd_config");
        builder.copy("test-container/trusted_ca_keys", "/etc/ssh/trusted_ca_keys");
        builder.copy("test-container/host_keys/*", "/etc/ssh/");

        builder.run("apk add --no-cache tini"
                + " && echo \"root:smile\" | chpasswd"
                + " && adduser -D -s /bin/ash sshj"
                + " && passwd -u sshj"
                + " && echo \"sshj:ultrapassword\" | chpasswd"
                + " && chmod 600 /home/sshj/.ssh/authorized_keys"
                + " && chmod 600 /etc/ssh/ssh_host_*_key"
                + " && chmod 644 /etc/ssh/*.pub"
                + " && chown -R sshj:sshj /home/sshj");
        builder.entryPoint("/sbin/tini", "/entrypoint.sh", "-o", "LogLevel=DEBUG2");
    }

    public SSHClient getConnectedClient(Config config) throws IOException {
        SSHClient sshClient = new SSHClient(config);
        sshClient.addHostKeyVerifier(new PromiscuousVerifier());
        sshClient.connect("127.0.0.1", getFirstMappedPort());

        return sshClient;
    }

    public SSHClient getConnectedClient() throws IOException {
        return getConnectedClient(new DefaultConfig());
    }
}
