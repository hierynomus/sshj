/*
 * Copyright 2010-2012 sshj contributors
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

import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
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
    public void init(File location) {
        final File f = new File(location + ".pub");
        if (f.exists())
            try {
                initPubKey(new FileReader(f));
            } catch (IOException e) {
                // let super provide both public & private key
                log.warn("Error reading public key file: {}", e.toString());
            }
        super.init(location);
    }

    @Override
    public void init(String privateKey, String publicKey) {
        if (publicKey != null) {
            initPubKey(new StringReader(publicKey));
        }
        super.init(privateKey, null);
    }

    /**
     * Read and store the separate public key provided alongside the private key
     *
     * @param publicKey Public key accessible through a {@code Reader}
     */
    private void initPubKey(Reader publicKey) {
        try {
            final BufferedReader br = new BufferedReader(publicKey);
            try {
                final String keydata = br.readLine();
                if (keydata != null) {
                    String[] parts = keydata.split(" ");
                    assert parts.length >= 2;
                    type = KeyType.fromString(parts[0]);
                    pubKey = new Buffer.PlainBuffer(Base64.decode(parts[1])).readPublicKey();
                }
            } finally {
                br.close();
            }
        } catch (IOException e) {
            // let super provide both public & private key
            log.warn("Error reading public key: {}", e.toString());
        }
    }
}
