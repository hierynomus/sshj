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
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.password.*;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/** Represents a PKCS8-encoded key file. This is the format used by OpenSSH and OpenSSL. */
public class PKCS8KeyFile
        implements FileKeyProvider {

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
    protected PasswordFinder pwdf;
    protected Resource<?> resource;
    protected KeyPair kp;

    protected KeyType type;

    protected char[] passphrase; // for blanking out

    @Override
    public PrivateKey getPrivate()
            throws IOException {
        return kp != null ? kp.getPrivate() : (kp = readKeyPair()).getPrivate();
    }

    @Override
    public PublicKey getPublic()
            throws IOException {
        return kp != null ? kp.getPublic() : (kp = readKeyPair()).getPublic();
    }

    @Override
    public KeyType getType()
            throws IOException {
        return type != null ? type : (type = KeyType.fromKey(getPublic()));
    }

    @Override
    public void init(Reader location) {
        assert location != null;
        resource = new PrivateKeyReaderResource(location);
    }

    @Override
    public void init(Reader location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(File location) {
        assert location != null;
        resource = new PrivateKeyFileResource(location.getAbsoluteFile());
    }

    @Override
    public void init(File location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(String privateKey, String publicKey) {
        assert privateKey != null;
        assert publicKey == null;
        resource = new PrivateKeyStringResource(privateKey);
    }

    @Override
    public void init(String privateKey, String publicKey, PasswordFinder pwdf) {
        init(privateKey, publicKey);
        this.pwdf = pwdf;
    }

    protected KeyPair readKeyPair()
            throws IOException {
        KeyPair kp = null;

        for (PEMParser r = null; ; ) {
            // while the PasswordFinder tells us we should retry
            try {
                r = new PEMParser(resource.getReader());
                final Object o = r.readObject();

                final JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
                pemConverter.setProvider("BC");

                if (o instanceof PEMEncryptedKeyPair) {
                    final PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) o;
                    JcePEMDecryptorProviderBuilder decryptorBuilder = new JcePEMDecryptorProviderBuilder();
                    decryptorBuilder.setProvider("BC");
                    try {
                        passphrase = pwdf == null ? null : pwdf.reqPassword(resource);
                        kp = pemConverter.getKeyPair(encryptedKeyPair.decryptKeyPair(decryptorBuilder.build(passphrase)));
                    } finally {
                        PasswordUtils.blankOut(passphrase);
                    }
                } else if (o instanceof PEMKeyPair) {
                    kp = pemConverter.getKeyPair((PEMKeyPair) o);
                } else {
                    log.debug("Expected PEMEncryptedKeyPair or PEMKeyPair, got: {}", o);
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
}
