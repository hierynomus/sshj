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

import java.io.IOException;
import java.security.KeyPair;


/**
 * Represents an OpenSSH identity that consists of a PEM-encoded PKCS8 or PKCS1 private key file and an
 * unencrypted public key file of the same name with the {@code ".pub"} extension. This allows to delay
 * requesting of the passphrase until the private key is requested.
 *
 * @see PKCS8KeyFile
 * @see BaseOpenSSHKeyFile
 */
public class OpenSSHKeyFile extends BaseOpenSSHKeyFile {

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

    @Override
    protected KeyPair readKeyPair() throws IOException {
        return parser.parseKeyPair(resource, pwdf);
    }

    @Override
    public String toString() {
        return "OpenSSHKeyFile{resource=" + resource + "}";
    }
}
