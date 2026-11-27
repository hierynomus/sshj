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
package net.schmizz.sshj.transport.kex;

import com.hierynomus.sshj.userauth.certificate.Certificate;
import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyFileUtil;
import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link KexHostKeyCertificateVerifier}, the host certificate check shared by the key exchanges, against
 * the real OpenSSH host certificates used by the other certificate tests. Those are issued for the host
 * {@code 127.0.0.1}.
 */
public class KexHostKeyCertificateVerifierTest {

    private static final String CERTIFICATES = "src/itest/resources/keyfiles/certificates/";

    private static final String VALID_CERT = "id_rsa_2048_pem_signed_by_rsa_host-cert.pub";

    private static final String EXPIRED_CERT = "id_ed25519_384_rfc4716_signed_by_rsa_host_valid_before_past-cert.pub";

    private static final String NOT_YET_VALID_CERT = "id_ed25519_384_rfc4716_signed_by_rsa_host_valid_after_future-cert.pub";

    private Transport transport;
    private Config config;

    @BeforeEach
    public void setUp() {
        transport = mock(Transport.class);
        config = mock(Config.class);
        when(transport.getConfig()).thenReturn(config);
        when(transport.getRemoteHost()).thenReturn("127.0.0.1");
        when(config.isVerifyHostKeyCertificates()).thenReturn(true);
    }

    @Test
    public void acceptsValidHostCertificate() throws Exception {
        final Certificate<?> cert = loadCertificate(VALID_CERT);

        assertDoesNotThrow(() -> KexHostKeyCertificateVerifier.verify(transport, cert, rawKey(cert)));
    }

    @Test
    public void ignoresKeysThatAreNotCertificates() throws Exception {
        final PublicKey plainKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();

        assertDoesNotThrow(() -> KexHostKeyCertificateVerifier.verify(transport, plainKey, new byte[0]));
        // a plain key never even consults the configuration
        verify(config, never()).isVerifyHostKeyCertificates();
    }

    @Test
    public void skipsVerificationWhenDisabledInConfig() throws Exception {
        when(config.isVerifyHostKeyCertificates()).thenReturn(false);
        // Would be rejected if checked: the certificate has expired.
        final Certificate<?> expired = loadCertificate(EXPIRED_CERT);

        assertDoesNotThrow(() -> KexHostKeyCertificateVerifier.verify(transport, expired, rawKey(expired)));
    }

    @Test
    public void rejectsExpiredCertificate() throws Exception {
        final Certificate<?> expired = loadCertificate(EXPIRED_CERT);

        final TransportException e = assertThrows(TransportException.class,
                () -> KexHostKeyCertificateVerifier.verify(transport, expired, rawKey(expired)));

        assertEquals(DisconnectReason.KEY_EXCHANGE_FAILED, e.getDisconnectReason());
        assertTrue(e.getMessage().contains("certificate check failed"), e.getMessage());
        assertTrue(e.getMessage().contains("valid before"), e.getMessage());
    }

    @Test
    public void rejectsCertificateThatIsNotValidYet() throws Exception {
        final Certificate<?> future = loadCertificate(NOT_YET_VALID_CERT);

        final TransportException e = assertThrows(TransportException.class,
                () -> KexHostKeyCertificateVerifier.verify(transport, future, rawKey(future)));

        assertEquals(DisconnectReason.KEY_EXCHANGE_FAILED, e.getDisconnectReason());
        assertTrue(e.getMessage().contains("valid after"), e.getMessage());
    }

    @Test
    public void rejectsCertificateForAnotherHost() throws Exception {
        when(transport.getRemoteHost()).thenReturn("not-the-certified-host.example.com");
        final Certificate<?> cert = loadCertificate(VALID_CERT);

        final TransportException e = assertThrows(TransportException.class,
                () -> KexHostKeyCertificateVerifier.verify(transport, cert, rawKey(cert)));

        assertEquals(DisconnectReason.KEY_EXCHANGE_FAILED, e.getDisconnectReason());
        assertTrue(e.getMessage().contains("doesn't match any of the principals"), e.getMessage());
    }

    @Test
    public void rejectsCertificateWhoseSignatureDoesNotVerify() throws Exception {
        final Certificate<?> cert = loadCertificate(VALID_CERT);
        final byte[] tampered = rawKey(cert);
        // Flip a bit in the signed portion: the CA signature no longer matches.
        tampered[tampered.length / 2] ^= 0x01;

        assertThrows(TransportException.class,
                () -> KexHostKeyCertificateVerifier.verify(transport, cert, tampered));
    }

    @Test
    public void wrapsUnparseableCertificateFields() {
        @SuppressWarnings("unchecked")
        final Certificate<PublicKey> broken = mock(Certificate.class);
        // Too short to hold even the length prefix of a string.
        when(broken.getSignature()).thenReturn(new byte[] {1});
        when(broken.getSignatureKey()).thenReturn(new byte[] {1});

        final TransportException e = assertThrows(TransportException.class,
                () -> KexHostKeyCertificateVerifier.verify(transport, broken, new byte[0]));

        assertEquals(DisconnectReason.KEY_EXCHANGE_FAILED, e.getDisconnectReason());
        assertNotNull(e.getCause(), "the parse failure should be kept as the cause");
    }

    private static Certificate<?> loadCertificate(final String name) throws IOException {
        try (FileReader reader = new FileReader(new File(CERTIFICATES + name))) {
            return (Certificate<?>) OpenSSHKeyFileUtil.initPubKey(reader).getPubKey();
        }
    }

    /** The certificate as it is sent as K_S, i.e. the bytes the CA signature was made over. */
    private static byte[] rawKey(final Certificate<?> cert) {
        return new Buffer.PlainBuffer().putPublicKey(cert).getCompactData();
    }
}
