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
import java.security.KeyPair;
import java.security.PublicKey;


/**
 * Represents an OpenSSH identity that consists of a PEM-encoded PKCS8 or PKCS1 private key file and an
 * unencrypted public key file of the same name with the {@code ".pub"} extension. This allows to delay
 * requesting of the passphrase until the private key is requested.
 *
 * @see PKCS8KeyFile
 */
public class OpenSSHKeyFile extends BaseFileKeyProvider {

    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new OpenSSHKeyFile();
        }

        @Override
        public String getName() {
            return "OpenSSH";
        }
    }

    private final KeyPairParser parser = new Pkcs8KeyPairParser();
    private final CompanionPublicKey companionPublicKey = new CompanionPublicKey();

    @Override
    protected KeyPair readKeyPair() throws IOException {
        return parser.parseKeyPair(resource, pwdf);
    }

    @Override
    public PublicKey getPublic()
            throws IOException {
        return companionPublicKey.isPresent() ? companionPublicKey.getPublicKey() : super.getPublic();
    }

    @Override
    public KeyType getType()
            throws IOException {
        return companionPublicKey.getType() != null ? companionPublicKey.getType() : super.getType();
    }

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
}
