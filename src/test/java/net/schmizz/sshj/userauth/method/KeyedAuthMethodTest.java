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
package net.schmizz.sshj.userauth.method;

import com.hierynomus.sshj.key.KeyAlgorithm;
import com.hierynomus.sshj.key.KeyAlgorithms;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.AuthParams;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link KeyedAuthMethod#getPublicKeyAlgorithm(KeyType)}'s use of the server's {@code
 * server-sig-algs} extension (RFC 8308) to prioritize candidate signature algorithms, without
 * ever dropping a client-configured candidate.
 */
class KeyedAuthMethodTest {

    private final Transport transport = mock(Transport.class);
    private final AuthParams params = mock(AuthParams.class);
    private TestableKeyedAuthMethod method;

    @BeforeEach
    void setUp() {
        when(params.getTransport()).thenReturn(transport);
        method = new TestableKeyedAuthMethod();
        method.init(params);
    }

    @Test
    void emptyServerListLeavesOrderUnchanged() throws Exception {
        givenClientAlgorithms(rsaSha512(), rsaSha256(), sshRsa());
        givenServerSigAlgs(); // none received

        assertThat(names(drainAll())).containsExactly("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa");
    }

    @Test
    void serverSubsetIsMovedToFront() throws Exception {
        givenClientAlgorithms(rsaSha512(), rsaSha256(), sshRsa());
        givenServerSigAlgs("ssh-rsa");

        assertThat(names(drainAll())).containsExactly("ssh-rsa", "rsa-sha2-512", "rsa-sha2-256");
    }

    @Test
    void noOverlapLeavesOrderUnchanged() throws Exception {
        givenClientAlgorithms(rsaSha512(), rsaSha256(), sshRsa());
        givenServerSigAlgs("ecdsa-sha2-nistp256"); // client has no ECDSA candidate here

        assertThat(names(drainAll())).containsExactly("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa");
    }

    @Test
    void reorderPreservesClientRelativeOrderNotServerOrder() throws Exception {
        givenClientAlgorithms(rsaSha512(), rsaSha256(), sshRsa());
        // Server lists ssh-rsa before rsa-sha2-256; the client's own relative preference
        // between its matched candidates must still win.
        givenServerSigAlgs("ssh-rsa", "rsa-sha2-256");

        assertThat(names(drainAll())).containsExactly("rsa-sha2-256", "ssh-rsa", "rsa-sha2-512");
    }

    @Test
    void singleCandidateIsAlwaysANoOp() throws Exception {
        givenClientAlgorithms(sshRsa());
        givenServerSigAlgs("rsa-sha2-512"); // present but irrelevant: client has only one candidate

        KeyAlgorithm ka = method.getPublicKeyAlgorithm(KeyType.RSA);

        assertThat(ka.getKeyAlgorithm()).isEqualTo("ssh-rsa");
        assertThat(method.shouldRetry()).isFalse();
    }

    @Test
    void clientAndServerAlgorithmsAreOnlyFetchedOnce() throws Exception {
        givenClientAlgorithms(rsaSha512(), sshRsa());
        givenServerSigAlgs("ssh-rsa");

        method.getPublicKeyAlgorithm(KeyType.RSA);
        method.getPublicKeyAlgorithm(KeyType.RSA);

        verify(transport, times(1)).getClientKeyAlgorithms(KeyType.RSA);
        verify(transport, times(1)).getServerSignatureAlgorithms();
    }

    private void givenClientAlgorithms(KeyAlgorithm... algorithms) throws TransportException {
        when(transport.getClientKeyAlgorithms(KeyType.RSA)).thenReturn(Arrays.asList(algorithms));
    }

    private void givenServerSigAlgs(String... names) {
        when(transport.getServerSignatureAlgorithms()).thenReturn(Arrays.asList(names));
    }

    /** Repeatedly calls getPublicKeyAlgorithm()/shouldRetry() to drain the whole candidate queue, in order. */
    private List<KeyAlgorithm> drainAll() throws TransportException {
        List<KeyAlgorithm> result = new ArrayList<>();
        KeyAlgorithm ka;
        do {
            ka = method.getPublicKeyAlgorithm(KeyType.RSA);
            result.add(ka);
        } while (method.shouldRetry());
        return result;
    }

    private static List<String> names(List<KeyAlgorithm> algorithms) {
        List<String> result = new ArrayList<>();
        for (KeyAlgorithm ka : algorithms) {
            result.add(ka.getKeyAlgorithm());
        }
        return result;
    }

    private static KeyAlgorithm rsaSha512() {
        return KeyAlgorithms.RSASHA512().create();
    }

    private static KeyAlgorithm rsaSha256() {
        return KeyAlgorithms.RSASHA256().create();
    }

    private static KeyAlgorithm sshRsa() {
        return KeyAlgorithms.SSHRSA().create();
    }

    /** Minimal concrete subclass; {@code KeyedAuthMethod} has no unimplemented abstract methods of its own. */
    private static class TestableKeyedAuthMethod extends KeyedAuthMethod {
        TestableKeyedAuthMethod() {
            super("test-method", mock(KeyProvider.class));
        }
    }
}
