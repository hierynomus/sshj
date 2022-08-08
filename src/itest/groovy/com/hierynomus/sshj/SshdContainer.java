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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.jetbrains.annotations.NotNull;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.dockerfile.DockerfileBuilder;
import org.testcontainers.utility.DockerLoggerFactory;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.concurrent.Future;

/**
 * A JUnit4 rule for launching a generic SSH server container.
 */
public class SshdContainer extends GenericContainer<SshdContainer> {
    /**
     * A workaround for strange logger names of testcontainers. They contain no dots, but contain slashes,
     * square brackets, and even emoji. It's uneasy to set the logging level via the XML file of logback, the
     * result would be less readable than the code below.
     */
    public static class DebugLoggingImageFromDockerfile extends ImageFromDockerfile {
        public DebugLoggingImageFromDockerfile() {
            super();
            Logger logger = (Logger) LoggerFactory.getILoggerFactory()
                    .getLogger(DockerLoggerFactory.getLogger(getDockerImageName()).getName());
            logger.setLevel(Level.DEBUG);
        }
    }

    public static class Builder {
        public static final String DEFAULT_SSHD_CONFIG = "" +
                "PermitRootLogin yes\n" +
                "AuthorizedKeysFile .ssh/authorized_keys\n" +
                "Subsystem sftp /usr/lib/ssh/sftp-server\n" +
                "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1\n" +
                "macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com\n" +
                "TrustedUserCAKeys /etc/ssh/trusted_ca_keys\n" +
                "Ciphers 3des-cbc,blowfish-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n" +
                "HostKey /etc/ssh/ssh_host_rsa_key\n" +
                "HostKey /etc/ssh/ssh_host_dsa_key\n" +
                "HostKey /etc/ssh/ssh_host_ecdsa_key\n" +
                "HostKey /etc/ssh/ssh_host_ed25519_key\n" +
                "HostKey /etc/ssh/ssh_host_ecdsa_256_key\n" +
                "HostCertificate /etc/ssh/ssh_host_ecdsa_256_key-cert.pub\n" +
                "HostKey /etc/ssh/ssh_host_ecdsa_384_key\n" +
                "HostCertificate /etc/ssh/ssh_host_ecdsa_384_key-cert.pub\n" +
                "HostKey /etc/ssh/ssh_host_ecdsa_521_key\n" +
                "HostCertificate /etc/ssh/ssh_host_ecdsa_521_key-cert.pub\n" +
                "HostKey /etc/ssh/ssh_host_ed25519_384_key\n" +
                "HostCertificate /etc/ssh/ssh_host_ed25519_384_key-cert.pub\n" +
                "HostKey /etc/ssh/ssh_host_rsa_2048_key\n" +
                "HostCertificate /etc/ssh/ssh_host_rsa_2048_key-cert.pub\n" +
                "LogLevel DEBUG2\n";

        public static void defaultDockerfileBuilder(@NotNull DockerfileBuilder builder) {
            builder.from("sickp/alpine-sshd:7.5-r2");

            builder.add("authorized_keys", "/home/sshj/.ssh/authorized_keys");

            builder.add("test-container/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ecdsa_key");
            builder.add("test-container/ssh_host_ecdsa_key.pub", "/etc/ssh/ssh_host_ecdsa_key.pub");
            builder.add("test-container/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key");
            builder.add("test-container/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_ed25519_key.pub");
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

            builder.add("sshd_config", "/etc/ssh/sshd_config");
        }

        private @NotNull String sshdConfig = DEFAULT_SSHD_CONFIG;

        public @NotNull Builder withSshdConfig(@NotNull String sshdConfig) {
            this.sshdConfig = sshdConfig;
            return this;
        }

        public @NotNull SshdContainer build() {
            return new SshdContainer(buildInner());
        }

        private @NotNull Future<String> buildInner() {
            return new DebugLoggingImageFromDockerfile()
                    .withDockerfileFromBuilder(Builder::defaultDockerfileBuilder)
                    .withFileFromPath(".", Paths.get("src/itest/docker-image"))
                    .withFileFromString("sshd_config", sshdConfig);
        }
    }

    @SuppressWarnings("unused")  // Used dynamically by Spock
    public SshdContainer() {
        this(new SshdContainer.Builder().buildInner());
    }

    public SshdContainer(@NotNull Future<String> future) {
        super(future);
        withExposedPorts(22);
        setWaitStrategy(new SshServerWaitStrategy());
        withLogConsumer(outputFrame -> {
            switch (outputFrame.getType()) {
                case STDOUT:
                    logger().info("sshd stdout: {}", outputFrame.getUtf8String().stripTrailing());
                    break;
                case STDERR:
                    logger().info("sshd stderr: {}", outputFrame.getUtf8String().stripTrailing());
                    break;
            }
        });
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
