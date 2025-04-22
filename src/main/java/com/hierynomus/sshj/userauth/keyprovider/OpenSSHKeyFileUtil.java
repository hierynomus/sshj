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

import net.schmizz.sshj.common.Base64DecodingException;
import net.schmizz.sshj.common.Base64Decoder;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.security.PublicKey;

public class OpenSSHKeyFileUtil {
    private OpenSSHKeyFileUtil() {
    }

    public static File getPublicKeyFile(File privateKeyFile) {
        File pubKey = new File(privateKeyFile + "-cert.pub");
        if (!pubKey.exists()) {
            pubKey = new File(privateKeyFile + ".pub");
        }
        if (pubKey.exists()) {
            return pubKey;
        }
        return null;
    }

    /**
     * Read the separate public key provided alongside the private key
     *
     * @param publicKey Public key accessible through a {@code Reader}
     */
    public static ParsedPubKey initPubKey(Reader publicKey) throws IOException {
        try (BufferedReader br = new BufferedReader(publicKey)) {
            String keydata;
            while ((keydata = br.readLine()) != null) {
                keydata = keydata.trim();
                if (!keydata.isEmpty()) {
                    String[] parts = keydata.trim().split("\\s+");
                    if (parts.length >= 2) {
                        byte[] decodedPublicKey = Base64Decoder.decode(parts[1]);
                        return new ParsedPubKey(
                                KeyType.fromString(parts[0]),
                                new Buffer.PlainBuffer(decodedPublicKey).readPublicKey()
                        );
                    } else {
                        throw new IOException("Got line with only one column");
                    }
                }
            }
            throw new IOException("Public key file is blank");
        } catch (Base64DecodingException err) {
            throw new IOException("Public key decoding failed", err);
        }
    }


    public static class ParsedPubKey {
        private final KeyType type;
        private final PublicKey pubKey;

        public ParsedPubKey(KeyType type, PublicKey pubKey) {
            this.type = type;
            this.pubKey = pubKey;
        }

        public KeyType getType() {
            return type;
        }

        public PublicKey getPubKey() {
            return pubKey;
        }
    }
}
