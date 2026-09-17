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
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;

/**
 * Shared helper for key-exchange implementations that need to validate an OpenSSH
 * host certificate after the host-key signature has been verified.
 */
final class KexHostKeyCertificateVerifier {

    private static final Logger log = LoggerFactory.getLogger(KexHostKeyCertificateVerifier.class);

    private KexHostKeyCertificateVerifier() {
    }

    /**
     * If {@code hostKey} is an OpenSSH certificate and host-certificate verification is
     * enabled in the {@link net.schmizz.sshj.Config}, validate it (signature, principals,
     * validity window) using {@link KeyType.CertUtils#verifyHostCertificate}. No-op otherwise.
     */
    static void verify(Transport trans, PublicKey publicKey, byte[] K_S) throws TransportException {
        if (publicKey instanceof Certificate<?> && trans.getConfig().isVerifyHostKeyCertificates()) {
            final Certificate<?> hostKey = (Certificate<?>) publicKey;
            String signatureType, caKeyType;
            try {
                signatureType = new Buffer.PlainBuffer(hostKey.getSignature()).readString();
            } catch (Buffer.BufferException e) {
                signatureType = null;
            }
            try {
                caKeyType = new Buffer.PlainBuffer(hostKey.getSignatureKey()).readString();
            } catch (Buffer.BufferException e) {
                caKeyType = null;
            }
            log.debug("Verifying signature of the key with type {} (signature type {}, CA key type {})",
                      hostKey.getType(), signatureType, caKeyType);

            try {
                final String certError = KeyType.CertUtils.verifyHostCertificate(K_S, hostKey, trans.getRemoteHost());
                if (certError != null) {
                    throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                                                 "KeyExchange certificate check failed: " + certError);
                }
            } catch (Buffer.BufferException | SSHRuntimeException e) {
                throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                                             "KeyExchange certificate check failed", e);
            }
        }
    }
}
