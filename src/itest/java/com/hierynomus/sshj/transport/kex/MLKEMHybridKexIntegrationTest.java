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
package com.hierynomus.sshj.transport.kex;

import com.hierynomus.sshj.SshdContainer;
import com.hierynomus.sshj.SshdContainer.SshdConfigBuilder;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.kex.MLKEM768X25519SHA256;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies interop with a real OpenSSH server (10.x) for the post-quantum hybrid key
 * exchange {@code mlkem768x25519-sha256}.
 *
 * <p>The container is built on Alpine&nbsp;3.22, whose {@code openssh} package is
 * 10.0p1 — the first OpenSSH release that ships {@code mlkem768x25519-sha256} (it is
 * the default KEX in 10.x). The {@link SshdConfigBuilder} {@code KexAlgorithms} line is
 * replaced with one containing only {@code mlkem768x25519-sha256} to ensure negotiation
 * cannot fall through to a classical KEX.</p>
 */
@Testcontainers
public class MLKEMHybridKexIntegrationTest {

    private static final String OPENSSH_10_BASE_IMAGE = "alpine:3.22";
    private static final String HYBRID_KEX_NAME = "mlkem768x25519-sha256";

    /**
     * sshd_config without a {@code KexAlgorithms} line. Required because in
     * {@code sshd_config} the first occurrence of an option wins, so we cannot simply
     * append our hybrid-only line on top of {@link SshdConfigBuilder#DEFAULT_SSHD_CONFIG}
     * (which already declares a classical-only {@code KexAlgorithms}). We then add the
     * hybrid line via {@link SshdConfigBuilder#with(String, String)}.
     */
    private static final String SSHD_CONFIG_NO_KEX = ""
            + "PermitRootLogin yes\n"
            + "AuthorizedKeysFile .ssh/authorized_keys\n"
            + "Subsystem sftp /usr/lib/ssh/sftp-server\n"
            + "macs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512\n"
            + "TrustedUserCAKeys /etc/ssh/trusted_ca_keys\n"
            + "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n"
            + "LogLevel DEBUG2\n";

    @Container
    private static final SshdContainer sshd = SshdContainer.Builder.defaultBuilder()
            .withBaseImage(OPENSSH_10_BASE_IMAGE)
            .withSshdConfig(new SshdConfigBuilder(SSHD_CONFIG_NO_KEX)
                    .with("KexAlgorithms", HYBRID_KEX_NAME))
            .withAllKeys()
            .build();

    @Test
    public void shouldNegotiateMlkem768X25519Sha256WithOpenSsh10() throws Throwable {
        final Config config = new DefaultConfig();
        // Force sshj to offer ONLY the hybrid KEX so the assertion below cannot pass by
        // falling back to a classical one.
        config.setKeyExchangeFactories(Collections.singletonList(new MLKEM768X25519SHA256.Factory()));

        final AtomicReference<String> negotiatedKex = new AtomicReference<>();
        try (SSHClient client = new SSHClient(config)) {
            client.addHostKeyVerifier(new PromiscuousVerifier());
            client.addAlgorithmsVerifier(algorithms -> {
                negotiatedKex.set(algorithms.getKeyExchangeAlgorithm());
                return true;
            });
            client.connect("127.0.0.1", sshd.getFirstMappedPort());

            client.authPublickey("sshj", "src/itest/resources/keyfiles/id_rsa_opensshv1");
            assertTrue(client.isAuthenticated(), "public-key auth should succeed over the hybrid KEX");
        }

        assertEquals(HYBRID_KEX_NAME, negotiatedKex.get(),
                "transport must have negotiated mlkem768x25519-sha256 with the OpenSSH 10 server");
    }
}
