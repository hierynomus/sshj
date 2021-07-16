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
package net.schmizz.sshj.userauth.keyprovider;

import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

/** Represents a PKCS8-encoded key file. This is the format used by (old-style) OpenSSH and OpenSSL. */
public class PKCS8KeyFile extends BaseFileKeyProvider {

    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new PKCS8KeyFile();
        }

        @Override
        public String getName() {
            return "PKCS8";
        }
    }

    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected char[] passphrase; // for blanking out


    protected KeyPair readKeyPair()
            throws IOException {
        KeyPair kp = null;

        for (PEMParser r = null; ; ) {
            // while the PasswordFinder tells us we should retry
            try {
                r = new PEMParser(resource.getReader());
                final Object o = r.readObject();

                final JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
                if (SecurityUtils.getSecurityProvider() != null) {
                    pemConverter.setProvider(SecurityUtils.getSecurityProvider());
                }

                if (o instanceof PEMEncryptedKeyPair) {
                    final PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) o;
                    JcePEMDecryptorProviderBuilder decryptorBuilder = new JcePEMDecryptorProviderBuilder();
                    if (SecurityUtils.getSecurityProvider() != null) {
                        decryptorBuilder.setProvider(SecurityUtils.getSecurityProvider());
                    }
                    try {
                        passphrase = pwdf == null ? null : pwdf.reqPassword(resource);
                        kp = pemConverter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptorBuilder.build(passphrase)));
                    } finally {
                        PasswordUtils.blankOut(passphrase);
                    }
                } else if (o instanceof PEMKeyPair) {
                    kp = pemConverter.getKeyPair((PEMKeyPair) o);
                } else if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
                    final PKCS8EncryptedPrivateKeyInfo encryptedInfo = (PKCS8EncryptedPrivateKeyInfo) o;
                    JceOpenSSLPKCS8DecryptorProviderBuilder decryptorBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
                    if (SecurityUtils.getSecurityProvider() != null) {
                        decryptorBuilder.setProvider(SecurityUtils.getSecurityProvider());
                    }
                    try {
                        passphrase = pwdf == null ? null : pwdf.reqPassword(resource);
                        PrivateKeyInfo pki = encryptedInfo.decryptPrivateKeyInfo(decryptorBuilder.build(passphrase));
                        kp = getKeyPair(pemConverter, pki);
                    } catch (OperatorCreationException e) {
                        throw new IOException(e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new IOException(e);
                    } catch (InvalidKeySpecException e) {
                        throw new IOException(e);
                    } catch (PKCSException e) {
                        throw new IOException(e);
                    } finally {
                        PasswordUtils.blankOut(passphrase);
                    }
                } else if (o instanceof PrivateKeyInfo) {
                    try {
                        kp = getKeyPair(pemConverter, (PrivateKeyInfo)o);
                    } catch (NoSuchAlgorithmException e) {
                        throw new IOException(e);
                    } catch (InvalidKeySpecException e) {
                        throw new IOException(e);
                    }
                } else {
                    log.debug("Expected PEMEncryptedKeyPair, PEMKeyPair, PKCS8EncryptedPrivateKeyInfo or PrivateKeyInfo, got: {}", o);
                }

            } catch (EncryptionException e) {
                if (pwdf != null && pwdf.shouldRetry(resource))
                    continue;
                else
                    throw e;
            } finally {
                IOUtils.closeQuietly(r);
            }
            break;
        }

        if (kp == null)
            throw new IOException("Could not read key pair from: " + resource);
        return kp;
    }

    @Override
    public String toString() {
        return "PKCS8KeyFile{resource=" + resource + "}";
    }

    private KeyPair getKeyPair(JcaPEMKeyConverter pemConverter, PrivateKeyInfo pki) throws PEMException, NoSuchAlgorithmException, InvalidKeySpecException {
        // get the private key
        RSAPrivateKey privateKey = (RSAPrivateKey)pemConverter.getPrivateKey(pki);
        BigInteger publicExponent = BigInteger.valueOf(65537);
        if (privateKey instanceof RSAPrivateCrtKey) {
            publicExponent = ((RSAPrivateCrtKey)privateKey).getPublicExponent();
        }

        // get the public key
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return new KeyPair(publicKey, privateKey);
    }
}
