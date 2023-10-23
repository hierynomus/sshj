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

import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyFileUtil;
import net.schmizz.sshj.userauth.password.PasswordFinder;

import java.io.*;
import java.security.PublicKey;


/**
 * Represents an OpenSSH identity that consists of a PKCS8-encoded private key file and an unencrypted public key file
 * of the same name with the {@code ".pub"} extension. This allows to delay requesting of the passphrase until the
 * private key is requested.
 *
 * @see PKCS8KeyFile
 */
public class OpenSSHKeyFile
        extends PKCS8KeyFile {

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

    private PublicKey pubKey;

    @Override
    public PublicKey getPublic()
            throws IOException {
        return pubKey != null ? pubKey : super.getPublic();
    }

    @Override
    public void init(File location, PasswordFinder pwdf) {
        // try cert key location first
        File pubKey = OpenSSHKeyFileUtil.getPublicKeyFile(location);
        if (pubKey != null) {
            try {
                initPubKey(new FileReader(pubKey));
            } catch (IOException e) {
                // let super provide both public & private key
                log.warn("Error reading public key file: {}", e.toString());
            }
        }
        super.init(location, pwdf);
    }

    @Override
    public void init(String privateKey, String publicKey, PasswordFinder pwdf) {
        if (publicKey != null) {
            try {
                initPubKey(new StringReader(publicKey));
            } catch (IOException e) {
                // let super provide both public & private key
                log.warn("Error reading public key: {}", e.toString());
            }
        }
        super.init(privateKey, null, pwdf);
    }

    @Override
    public void init(Reader privateKey, Reader publicKey, PasswordFinder pwdf) {
        if (publicKey != null) {
            try {
                initPubKey(publicKey);
            } catch (IOException e) {
                // let super provide both public & private key
                log.warn("Error reading public key: {}", e.toString());
            }
        }
        super.init(privateKey, null, pwdf);
    }

    /**
     * Read and store the separate public key provided alongside the private key
     *
     * @param publicKey Public key accessible through a {@code Reader}
     */
    private void initPubKey(Reader publicKey) throws IOException {
        OpenSSHKeyFileUtil.ParsedPubKey parsed = OpenSSHKeyFileUtil.initPubKey(publicKey);
        type = parsed.getType();
        pubKey = parsed.getPubKey();
    }
}
