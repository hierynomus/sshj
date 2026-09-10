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
package com.hierynomus.sshj.userauth.keyprovider;

import net.schmizz.sshj.common.KeyType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.PublicKey;

/**
 * The public key - or certificate - provided alongside a private key for the OpenSSH key file
 * providers ({@link net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile} and
 * {@link OpenSSHKeyV1KeyFile}). It can be supplied next to the private key as a {@code .pub} /
 * {@code -cert.pub} file, or explicitly as a string or a stream. When none was supplied, the
 * providers fall back to the public key embedded in the private key file.
 * <p>
 * A parse failure is logged and otherwise ignored, again letting the provider fall back to the
 * embedded public key.
 */
public class CompanionPublicKey {

    private static final Logger log = LoggerFactory.getLogger(CompanionPublicKey.class);

    private KeyType type;
    private PublicKey publicKey;

    /** Load the {@code .pub} / {@code -cert.pub} file that sits next to the given private key file, if any. */
    public void loadSiblingOf(File privateKeyLocation) {
        File publicKeyFile = OpenSSHKeyFileUtil.getPublicKeyFile(privateKeyLocation);
        if (publicKeyFile != null) {
            try {
                parse(new FileReader(publicKeyFile));
            } catch (IOException e) {
                // let the provider fall back to the public key embedded in the private key file
                log.warn("Error reading public key file: {}", e.toString());
            }
        }
    }

    /** Load the public key from the given string, or do nothing when it is {@code null}. */
    public void load(String publicKey) {
        if (publicKey != null) {
            load(new StringReader(publicKey));
        }
    }

    /** Load the public key from the given stream, or do nothing when it is {@code null}. */
    public void load(Reader publicKey) {
        if (publicKey != null) {
            try {
                parse(publicKey);
            } catch (IOException e) {
                // let the provider fall back to the public key embedded in the private key file
                log.warn("Error reading public key: {}", e.toString());
            }
        }
    }

    private void parse(Reader reader) throws IOException {
        OpenSSHKeyFileUtil.ParsedPubKey parsed = OpenSSHKeyFileUtil.initPubKey(reader);
        type = parsed.getType();
        publicKey = parsed.getPubKey();
    }

    public boolean isPresent() {
        return publicKey != null;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public KeyType getType() {
        return type;
    }
}
