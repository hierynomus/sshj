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
import org.junit.jupiter.api.function.ThrowingConsumer;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.dockerfile.DockerfileBuilder;
import org.testcontainers.utility.DockerLoggerFactory;

import java.util.function.Consumer;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;

/**
 * A JUnit4 rule for launching a generic SSH server container.
 */
public class SshdContainer extends GenericContainer<SshdContainer> {

    /**
     * A workaround for strange logger names of testcontainers. They contain no
     * dots, but contain slashes,
     * square brackets, and even emoji. It's uneasy to set the logging level via the
     * XML file of logback, the
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

    public static class SshdConfigBuilder {
        public static final String DEFAULT_SSHD_CONFIG = "" +
                "PermitRootLogin yes\n" +
                "AuthorizedKeysFile .ssh/authorized_keys\n" +
                "Subsystem sftp /usr/lib/ssh/sftp-server\n" +
                "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1\n"
                +
                "macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512\n"
                +
                "TrustedUserCAKeys /etc/ssh/trusted_ca_keys\n" +
                "Ciphers 3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n"
                +
                "LogLevel DEBUG2\n";
        private String sshdConfig;

        public SshdConfigBuilder(@NotNull String sshdConfig) {
            this.sshdConfig = sshdConfig;
        }

        public static SshdConfigBuilder defaultBuilder() {
            return new SshdConfigBuilder(DEFAULT_SSHD_CONFIG);
        }

        public @NotNull SshdConfigBuilder withHostKey(@NotNull String hostKey) {
            sshdConfig += "HostKey /etc/ssh/" + Paths.get(hostKey).getFileName() + "\n";
            return this;
        }

        public @NotNull SshdConfigBuilder withHostKeyCertificate(@NotNull String hostKeyCertificate) {
            sshdConfig += "HostCertificate /etc/ssh/" + Paths.get(hostKeyCertificate).getFileName() + "\n";
            return this;
        }

        public @NotNull SshdConfigBuilder with(String key, String value) {
            sshdConfig += key + " " + value + "\n";
            return this;
        }

        public @NotNull String build() {
            return sshdConfig;
        }
    }

    public static class Builder implements Consumer<DockerfileBuilder> {
        private List<String> hostKeys = new ArrayList<>();
        private List<String> certificates = new ArrayList<>();
        private @NotNull SshdConfigBuilder sshdConfig = SshdConfigBuilder.defaultBuilder();

        public static Builder defaultBuilder() {
            Builder b = new Builder();

            return b;
        }


        public @NotNull Builder withSshdConfig(@NotNull SshdConfigBuilder sshdConfig) {
            this.sshdConfig = sshdConfig;
            return this;
        }

        public @NotNull Builder withAllKeys() {
            this.addHostKey("test-container/ssh_host_ecdsa_key");
            this.addHostKey("test-container/ssh_host_ed25519_key");
            this.addHostKey("test-container/host_keys/ssh_host_ecdsa_256_key");
            this.addHostKey("test-container/host_keys/ssh_host_ecdsa_384_key");
            this.addHostKey("test-container/host_keys/ssh_host_ecdsa_521_key");
            this.addHostKey("test-container/host_keys/ssh_host_ed25519_384_key");
            this.addHostKey("test-container/host_keys/ssh_host_rsa_2048_key");
            this.addHostKeyCertificate("test-container/host_keys/ssh_host_ecdsa_256_key-cert.pub");
            this.addHostKeyCertificate("test-container/host_keys/ssh_host_ecdsa_384_key-cert.pub");
            this.addHostKeyCertificate("test-container/host_keys/ssh_host_ecdsa_521_key-cert.pub");
            this.addHostKeyCertificate("test-container/host_keys/ssh_host_ed25519_384_key-cert.pub");
            this.addHostKeyCertificate("test-container/host_keys/ssh_host_rsa_2048_key-cert.pub");
            return this;
        }

        public @NotNull SshdContainer build() {
            return new SshdContainer(buildInner());
        }

        @NotNull Future<String> buildInner() {
            return new DebugLoggingImageFromDockerfile()
                    .withDockerfileFromBuilder(this)
                    .withFileFromPath(".", Paths.get("src/itest/docker-image"))
                    .withFileFromString("sshd_config", sshdConfig.build());
        }

        public void accept(@NotNull DockerfileBuilder builder) {
            builder.from("alpine:3.18.3");
            builder.run("apk add --no-cache openssh");
            builder.expose(22);
            builder.copy("entrypoint.sh", "/entrypoint.sh");

            builder.add("authorized_keys", "/home/sshj/.ssh/authorized_keys");
            builder.copy("test-container/trusted_ca_keys", "/etc/ssh/trusted_ca_keys");

            for (String hostKey : hostKeys) {
                builder.copy(hostKey, "/etc/ssh/" + Paths.get(hostKey).getFileName());
                builder.copy(hostKey + ".pub", "/etc/ssh/" + Paths.get(hostKey).getFileName() + ".pub");
            }

            for (String certificate : certificates) {
                builder.copy(certificate, "/etc/ssh/" + Paths.get(certificate).getFileName());
            }


            builder.run("apk add --no-cache tini"
                    + " && echo \"root:smile\" | chpasswd"
                    + " && adduser -D -s /bin/ash sshj"
                    + " && passwd -u sshj"
                    + " && echo \"sshj:ultrapassword\" | chpasswd"
                    + " && chmod 600 /home/sshj/.ssh/authorized_keys"
                    + " && chmod 600 /etc/ssh/ssh_host_*_key"
                    + " && chmod 644 /etc/ssh/*.pub"
                    + " && chmod 755 /entrypoint.sh"
                    + " && chown -R sshj:sshj /home/sshj");
            builder.entryPoint("/sbin/tini", "/entrypoint.sh", "-o", "LogLevel=DEBUG2");

            builder.add("sshd_config", "/etc/ssh/sshd_config");
        }

        public @NotNull Builder addHostKey(@NotNull String hostKey) {
            hostKeys.add(hostKey);
            sshdConfig.withHostKey(hostKey);
            return this;
        }

        public @NotNull Builder addHostKeyCertificate(@NotNull String hostKeyCertificate) {
            certificates.add(hostKeyCertificate);
            sshdConfig.withHostKeyCertificate(hostKeyCertificate);
            return this;
        }
    }

    @SuppressWarnings("unused") // Used dynamically by Spock
    public SshdContainer() {
        this(new SshdContainer.Builder().withAllKeys().buildInner());
    }

    public SshdContainer(SshdContainer.Builder builder) {
        this(builder.buildInner());
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

    public static void withSshdContainer(SshdContainer.Builder builder, @NotNull ThrowingConsumer<SshdContainer> consumer) throws Throwable {
        SshdContainer sshdContainer = new SshdContainer(builder.buildInner());
        sshdContainer.start();
        try {
            consumer.accept(sshdContainer);
        } finally {
            sshdContainer.stop();
        }
    }
}
