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
package com.hierynomus.sshj.userauth.method;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.AbstractService;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.userauth.UserAuth;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end proof that publickey auth against a real (in-process Apache MINA) SSH server both
 * receives a real {@code server-sig-algs} extension (RFC 8308) via {@code SSH_MSG_EXT_INFO}, and
 * that {@link net.schmizz.sshj.userauth.method.KeyedAuthMethod} actually reorders its candidate
 * signature algorithms because of it - not just that auth still succeeds regardless (which it
 * would even without this feature, since the test server accepts any algorithm eventually).
 * <p/>
 * The embedded server is restricted to a signature-factory set that excludes {@code
 * rsa-sha2-512} - sshj's own default top preference for an RSA key - so if {@code
 * server-sig-algs} is genuinely consulted, the very first publickey attempt must use {@code
 * rsa-sha2-256} instead. A {@link Proxy}-based spy on the real {@link Transport} used by the auth
 * flow records the algorithm name of every unsigned publickey "feeler" request sent, in order.
 */
public class AuthPublickeyExtInfoTest {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension(false);

    @BeforeEach
    public void setUp() throws IOException {
        fixture.getServer().setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        // Deliberately excludes rsa-sha2-512, which sshj tries first by default for an RSA key.
        fixture.getServer().setSignatureFactoriesNames("ssh-rsa", "rsa-sha2-256");
        fixture.getServer().start();
    }

    @Test
    public void reordersFirstPublickeyAttemptToMatchServerSigAlgs() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        KeyProvider keyProvider = new KeyProvider() {
            @Override
            public PrivateKey getPrivate() {
                return keyPair.getPrivate();
            }

            @Override
            public PublicKey getPublic() {
                return keyPair.getPublic();
            }

            @Override
            public KeyType getType() {
                return KeyType.RSA;
            }
        };

        SSHClient client = fixture.setupConnectedDefaultClient();

        // Grab the real, already-connected Transport (kex - and EXT_INFO parsing - has already
        // happened by now) before wrapping it, so we can independently confirm what the server
        // actually advertised.
        Transport realTransport = getUserAuthTransport(client);
        List<String> attemptedAlgorithms = Collections.synchronizedList(new ArrayList<>());
        installPublickeyAttemptSpy(client, realTransport, attemptedAlgorithms);

        client.auth("jeroen", new AuthPublickey(keyProvider));

        assertTrue(client.isAuthenticated(), "client should authenticate with an RSA key");

        assertThat(realTransport.getServerSignatureAlgorithms())
                .as("the embedded MINA server must have advertised server-sig-algs restricted to what we configured")
                .containsExactlyInAnyOrder("ssh-rsa", "rsa-sha2-256");

        assertThat(attemptedAlgorithms)
                .as("the first publickey attempt must use an algorithm the server actually accepts (rsa-sha2-256), "
                        + "proving KeyedAuthMethod reordered based on the real server-sig-algs extension rather "
                        + "than sshj's own default preference (rsa-sha2-512 first)")
                .startsWith("rsa-sha2-256");
    }

    /**
     * Replaces the {@link Transport} that the client's userauth service ({@code UserAuthImpl},
     * reached via its {@code AbstractService.trans} field) uses, with a {@link Proxy} that
     * forwards every call to the real transport but first records the algorithm name of any
     * unsigned publickey "feeler" {@code SSH_MSG_USERAUTH_REQUEST} passed to {@code write(...)}.
     */
    private void installPublickeyAttemptSpy(SSHClient client, Transport realTransport, List<String> attemptedAlgorithms)
            throws Exception {
        Transport spy = (Transport) Proxy.newProxyInstance(
                Transport.class.getClassLoader(),
                new Class<?>[]{Transport.class},
                (InvocationHandler) (proxy, method, args) -> {
                    if ("write".equals(method.getName()) && args != null && args.length == 1 && args[0] instanceof SSHPacket) {
                        recordIfPublickeyFeeler((SSHPacket) args[0], attemptedAlgorithms);
                    }
                    try {
                        return method.invoke(realTransport, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });

        Field userAuthTransField = AbstractService.class.getDeclaredField("trans");
        userAuthTransField.setAccessible(true);
        userAuthTransField.set(client.getUserAuth(), spy);
    }

    private static Transport getUserAuthTransport(SSHClient client) throws Exception {
        UserAuth userAuth = client.getUserAuth();
        Field transField = AbstractService.class.getDeclaredField("trans");
        transField.setAccessible(true);
        return (Transport) transField.get(userAuth);
    }

    private static void recordIfPublickeyFeeler(SSHPacket original, List<String> attemptedAlgorithms) {
        try {
            SSHPacket copy = new SSHPacket(original);
            if (copy.readMessageID() != Message.USERAUTH_REQUEST) {
                return;
            }
            copy.readString(); // username
            copy.readString(); // next service name
            String authMethodName = copy.readString();
            if (!"publickey".equals(authMethodName)) {
                return;
            }
            boolean hasSignature = copy.readBoolean();
            if (hasSignature) {
                return; // the signed follow-up doesn't reveal a new candidate; only the feeler does
            }
            attemptedAlgorithms.add(copy.readString());
        } catch (Buffer.BufferException e) {
            // Not a packet shaped the way we expect (e.g. a transport-layer packet); ignore.
        }
    }
}
