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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.sshj.SshdContainer.SshdConfigBuilder;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;

@Testcontainers
public class PublicKeyAuthTest {
    @Container
    private static final SshdContainer sshd = new SshdContainer(SshdContainer.Builder.defaultBuilder().withSshdConfig(
            SshdConfigBuilder.defaultBuilder().with("PubkeyAcceptedAlgorithms", "+ssh-rsa-cert-v01@openssh.com"))
            .withAllKeys());

    public static Stream<Arguments> keys() {
        return Stream.of(
                Arguments.of("id_rsa2", null),
                // "id_ecdsa_nistp256" | null // TODO: Need to improve PKCS8 key support.
                Arguments.of("id_ecdsa_opensshv1", null),
                Arguments.of("id_ed25519_opensshv1", null),
                Arguments.of("id_ed25519_opensshv1_aes256cbc.pem", "foobar"),
                Arguments.of("id_ed25519_opensshv1_aes128cbc.pem", "sshjtest"),
                Arguments.of("id_ed25519_opensshv1_protected", "sshjtest"),
                Arguments.of("id_rsa", null),
                Arguments.of("id_rsa_opensshv1", null),
                Arguments.of("id_ecdsa_nistp384_opensshv1", null),
                Arguments.of("id_ecdsa_nistp521_opensshv1", null));
    }

    @ParameterizedTest(name = "should authenticate with signed public key {0}")
    @MethodSource("keys")
    public void shouldAuthenticateWithSignedRsaKey(String key, String passphrase) throws Throwable {
        try (SSHClient client = sshd.getConnectedClient()) {
            KeyProvider p = null;
            if (passphrase != null) {
                p = client.loadKeys("src/itest/resources/keyfiles/" + key, passphrase);
            } else {
                p = client.loadKeys("src/itest/resources/keyfiles/" + key);
            }
            client.authPublickey("sshj", p);

            assertTrue(client.isAuthenticated());
        }
    }

    @Test
    public void shouldNotAuthenticateWithUnknownKey() throws Throwable {
        try (SSHClient client = sshd.getConnectedClient()) {
            assertThrows(UserAuthException.class, () -> {
                client.authPublickey("sshj", "src/itest/resources/keyfiles/id_unknown_key");
            });

            assertFalse(client.isAuthenticated());
        }
    }

}
