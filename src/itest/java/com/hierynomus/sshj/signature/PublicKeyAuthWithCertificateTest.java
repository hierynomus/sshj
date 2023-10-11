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
package com.hierynomus.sshj.signature;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.SshdContainer;
import com.hierynomus.sshj.SshdContainer.SshdConfigBuilder;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;

@Testcontainers
public class PublicKeyAuthWithCertificateTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer(SshdContainer.Builder.defaultBuilder().withSshdConfig(SshdConfigBuilder.defaultBuilder().with("PubkeyAcceptedAlgorithms", "+ssh-rsa-cert-v01@openssh.com")).withAllKeys());

    public static Stream<String> keys() {
        return Stream.of(
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
        "id_ed25519_384_rfc4716_signed_by_rsa");
    }

    @ParameterizedTest(name = "should authenticate with signed public key {0}")
    @MethodSource("keys")
    public void shouldAuthenticateWithSignedPublicKey(String key) throws Throwable {
        Config c = new DefaultConfig();
        SSHClient client = sshd.getConnectedClient(c);

        client.authPublickey("sshj", "src/itest/resources/keyfiles/certificates/" + key);

        assertTrue(client.isAuthenticated());

        client.disconnect();
    }

}
