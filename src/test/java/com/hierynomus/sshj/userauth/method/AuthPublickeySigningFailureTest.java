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

import com.hierynomus.sshj.key.KeyAlgorithm;
import com.hierynomus.sshj.key.KeyAlgorithms;
import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.DefaultConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.signature.SignatureECDSA;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A key that fails to sign (e.g. a PKCS#11 token that was removed, or a failing JCA provider) must only fail that
 * authentication attempt. The failure used to escape on the transport reader thread and close the connection, so
 * the caller could not fall back to another method.
 */
public class AuthPublickeySigningFailureTest {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension(false);

    private KeyPair keyPair;

    @BeforeEach
    public void setUp() throws Exception {
        fixture.getServer().setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        fixture.getServer().start();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = kpg.generateKeyPair();
    }

    @Test
    public void sshRuntimeExceptionWhileSigningFailsOnlyTheAttempt() throws Exception {
        RuntimeException failure = new SSHRuntimeException(new java.security.SignatureException("token removed"));

        assertAttemptFailsButConnectionSurvives(() -> new FailingSignature(failure, null), failure.getCause());
    }

    @Test
    public void providerExceptionWhileSigningFailsOnlyTheAttempt() throws Exception {
        RuntimeException failure = new ProviderException("CKR_DEVICE_REMOVED");

        assertAttemptFailsButConnectionSurvives(() -> new FailingSignature(failure, null), failure);
    }

    @Test
    public void providerExceptionWhileInitializingSigningFailsOnlyTheAttempt() throws Exception {
        RuntimeException failure = new ProviderException("CKR_PIN_INCORRECT");

        assertAttemptFailsButConnectionSurvives(() -> new FailingSignature(null, failure), failure);
    }

    /** Programming errors are not authentication failures, they still take the connection down. */
    @Test
    public void unexpectedRuntimeExceptionStillClosesTheConnection() throws Exception {
        SSHClient client = clientSigningWith(() -> new FailingSignature(new IllegalStateException("bug"), null));

        assertThrows(Exception.class, () -> client.auth("test", new AuthPublickey(keyProvider())));

        assertThrows(Exception.class, () -> client.authPassword("test", "test"));
        assertFalse(client.isAuthenticated());
    }

    private void assertAttemptFailsButConnectionSurvives(Supplier<Signature> signature, Throwable expectedCause)
            throws Exception {
        SSHClient client = clientSigningWith(signature);

        UserAuthException e = assertThrows(UserAuthException.class,
                () -> client.auth("test", new AuthPublickey(keyProvider())));

        assertFalse(client.isAuthenticated());
        assertTrue(client.isConnected(), "the connection must survive a key that cannot sign");
        assertTrue(hasCause(e, expectedCause), "the cause of the signing failure should be preserved");

        client.authPassword("test", "test");
        assertTrue(client.isAuthenticated(), "should be able to fall back to another method on the same connection");
    }

    private SSHClient clientSigningWith(Supplier<Signature> signature) throws IOException {
        DefaultConfig config = new DefaultConfig();
        List<Factory.Named<KeyAlgorithm>> algorithms = new ArrayList<>(config.getKeyAlgorithms());
        algorithms.add(0, new KeyAlgorithms.Factory(KeyType.ECDSA256.toString(), new Factory.Named<Signature>() {
            @Override
            public Signature create() {
                return signature.get();
            }

            @Override
            public String getName() {
                return KeyType.ECDSA256.toString();
            }
        }, KeyType.ECDSA256));
        config.setKeyAlgorithms(algorithms);
        return fixture.connectClient(fixture.setupClient(config));
    }

    private KeyProvider keyProvider() {
        return new KeyProvider() {
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
                return KeyType.ECDSA256;
            }
        };
    }

    private static boolean hasCause(Throwable t, Throwable expected) {
        for (; t != null; t = t.getCause()) {
            if (t == expected) {
                return true;
            }
        }
        return false;
    }

    /** A real ECDSA signature, except that initSign()/sign() fail the way a broken token or provider would. */
    private static class FailingSignature implements Signature {
        private final Signature delegate = new SignatureECDSA.Factory256().create();
        private final RuntimeException signFailure;
        private final RuntimeException initSignFailure;

        FailingSignature(RuntimeException signFailure, RuntimeException initSignFailure) {
            this.signFailure = signFailure;
            this.initSignFailure = initSignFailure;
        }

        @Override
        public String getSignatureName() {
            return delegate.getSignatureName();
        }

        @Override
        public void initVerify(PublicKey pubkey) {
            delegate.initVerify(pubkey);
        }

        @Override
        public void initSign(PrivateKey prvkey) {
            if (initSignFailure != null) {
                throw initSignFailure;
            }
            delegate.initSign(prvkey);
        }

        @Override
        public void update(byte[] H) {
            delegate.update(H);
        }

        @Override
        public void update(byte[] H, int off, int len) {
            delegate.update(H, off, len);
        }

        @Override
        public byte[] sign() {
            if (signFailure != null) {
                throw signFailure;
            }
            return delegate.sign();
        }

        @Override
        public byte[] encode(byte[] signature) {
            return delegate.encode(signature);
        }

        @Override
        public boolean verify(byte[] sig) {
            return delegate.verify(sig);
        }
    }
}
