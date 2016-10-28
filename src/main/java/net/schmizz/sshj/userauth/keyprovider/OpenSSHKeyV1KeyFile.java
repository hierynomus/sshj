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

import java.io.BufferedReader;
import java.io.IOException;
import java.security.KeyPair;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.ByteArrayUtils;
import net.schmizz.sshj.common.IOUtils;

public class OpenSSHKeyV1KeyFile extends BaseFileKeyProvider {
    private static final Logger logger = LoggerFactory.getLogger(OpenSSHKeyV1KeyFile.class);
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes();

    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new OpenSSHKeyV1KeyFile();
        }

        @Override
        public String getName() {
            return "openssh-key-v1";
        }
    }

    @Override
    protected KeyPair readKeyPair() throws IOException {
        BufferedReader reader = new BufferedReader(resource.getReader());
        try {
            String line = reader.readLine();
            while (line != null && !line.startsWith(BEGIN)) {
                line = reader.readLine();
            }
            line = line.substring(BEGIN.length());
            if (!line.startsWith("OPENSSH PRIVATE KEY-----")) {
                throw new IOException("This key is not in 'openssh-key-v1' format");
            }

            StringBuffer stringBuffer = new StringBuffer();
            line = reader.readLine();
            while (!line.startsWith(END)) {
                stringBuffer.append(line);
                line = reader.readLine();
            }
            byte[] decode = Base64.decode(stringBuffer.toString());
            System.out.println(ByteArrayUtils.printHex(decode, 0, decode.length));
            Buffer.PlainBuffer keyBuffer = new Buffer.PlainBuffer(decode);
            byte[] bytes = new byte[AUTH_MAGIC.length];
            keyBuffer.readRawBytes(bytes);
            if (!ByteArrayUtils.equals(bytes, 0, AUTH_MAGIC, 0, AUTH_MAGIC.length)) {
                throw new IOException("This key does not contain the 'openssh-key-v1' format header");
            }

            String cipherName = keyBuffer.readString();
            String kdfName = keyBuffer.readString();
            String kdfOptions = keyBuffer.readString();

            if ("none".equals(cipherName)) {
                return readUnencrypted(keyBuffer);
            } else {
                logger.debug("Reading encrypted openssh-key-v1 file with cipher: " + cipherName);

                System.out.println(cipherName + " " + kdfName + " " + kdfOptions);
            }

        } finally {
            IOUtils.closeQuietly(reader);
        }

        return null;
    }

    private KeyPair readUnencrypted(final Buffer.PlainBuffer keyBuffer) throws IOException {
        int i = keyBuffer.readUInt32AsInt();
        if (i != 1) {
            throw new IOException("We don't support having more than 1 key in the file (yet).");
        }
        logger.info("reading {} keys", i);
        byte[] pubKey = keyBuffer.readBytes();
        logger.info("read key: {}", ByteArrayUtils.printHex(pubKey, 0, pubKey.length));
        int privKeyListSize = keyBuffer.readUInt32AsInt();
        if (privKeyListSize % 8 != 0) {
            throw new IOException("The private key section must be a multiple of the block size (8)");
        }
        int checkInt1 = keyBuffer.readUInt32AsInt();
        int checkInt2 = keyBuffer.readUInt32AsInt();
        logger.info("Read checkInts: {}, {}", checkInt1, checkInt2);
        byte[] privKey = keyBuffer.readBytes();
        logger.info("read key: {}", ByteArrayUtils.printHex(privKey, 0, privKey.length));

        return null;
    }
}
