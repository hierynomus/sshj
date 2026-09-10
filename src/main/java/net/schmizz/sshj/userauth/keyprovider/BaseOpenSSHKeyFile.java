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

import com.hierynomus.sshj.userauth.keyprovider.CompanionPublicKey;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.password.PasswordFinder;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.security.PublicKey;

/**
 * Base for the OpenSSH key file providers - {@link OpenSSHKeyFile} and the openssh-key-v1 provider.
 * <p>
 * These accept a public key, or certificate, supplied alongside the private key: as a {@code .pub} /
 * {@code -cert.pub} file next to it, or explicitly as a string or a stream. When one is present it is
 * used in place of the public key embedded in the private key file, and lets {@link #getPublic()} /
 * {@link #getType()} answer without decrypting the private key. When none was supplied the provider
 * falls back to the embedded public key.
 */
public abstract class BaseOpenSSHKeyFile extends BaseFileKeyProvider {

    protected final CompanionPublicKey companionPublicKey = new CompanionPublicKey();

    @Override
    public void init(File location, PasswordFinder pwdf) {
        companionPublicKey.loadSiblingOf(location);
        super.init(location, pwdf);
    }

    @Override
    public void init(String privateKey, String publicKey, PasswordFinder pwdf) {
        companionPublicKey.load(publicKey);
        super.init(privateKey, null, pwdf);
    }

    @Override
    public void init(Reader privateKey, Reader publicKey, PasswordFinder pwdf) {
        companionPublicKey.load(publicKey);
        super.init(privateKey, null, pwdf);
    }

    @Override
    public PublicKey getPublic() throws IOException {
        return companionPublicKey.isPresent() ? companionPublicKey.getPublicKey() : super.getPublic();
    }

    @Override
    public KeyType getType() throws IOException {
        return companionPublicKey.getType() != null ? companionPublicKey.getType() : super.getType();
    }
}
