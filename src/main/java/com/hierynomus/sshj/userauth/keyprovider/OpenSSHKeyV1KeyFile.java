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

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.common.Buffer.PlainBuffer;
import net.schmizz.sshj.userauth.keyprovider.BaseFileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Reads a key file in the new OpenSSH format.
 * The format is described in the following document: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
 */
public class OpenSSHKeyV1KeyFile extends BaseFileKeyProvider {
    private static final Logger logger = LoggerFactory.getLogger(OpenSSHKeyV1KeyFile.class);
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes();
    public static final String OPENSSH_PRIVATE_KEY = "OPENSSH PRIVATE KEY-----";

    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new OpenSSHKeyV1KeyFile();
        }

        @Override
        public String getName() {
            return KeyFormat.OpenSSHv1.name();
        }
    }

    @Override
    protected KeyPair readKeyPair() throws IOException {
        BufferedReader reader = new BufferedReader(resource.getReader());
        try {
            if (!checkHeader(reader)) {
                throw new IOException("This key is not in 'openssh-key-v1' format");
            }

            String keyFile = readKeyFile(reader);
            byte[] decode = Base64.decode(keyFile);
            PlainBuffer keyBuffer = new PlainBuffer(decode);
            return readDecodedKeyPair(keyBuffer);

        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }

    private KeyPair readDecodedKeyPair(final PlainBuffer keyBuffer) throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[AUTH_MAGIC.length];
        keyBuffer.readRawBytes(bytes); // byte[] AUTH_MAGIC
        if (!ByteArrayUtils.equals(bytes, 0, AUTH_MAGIC, 0, AUTH_MAGIC.length)) {
            throw new IOException("This key does not contain the 'openssh-key-v1' format magic header");
        }

        String cipherName = keyBuffer.readString(); // string ciphername
        String kdfName = keyBuffer.readString(); // string kdfname
        String kdfOptions = keyBuffer.readString(); // string kdfoptions

        int nrKeys = keyBuffer.readUInt32AsInt(); // int number of keys N; Should be 1
        if (nrKeys != 1) {
            throw new IOException("We don't support having more than 1 key in the file (yet).");
        }
        PublicKey publicKey = readPublicKey(new PlainBuffer(keyBuffer.readBytes())); // string publickey1
        PlainBuffer privateKeyBuffer = new PlainBuffer(keyBuffer.readBytes()); // string (possibly) encrypted, padded list of private keys
        if ("none".equals(cipherName)) {
            logger.debug("Reading unencrypted keypair");
            return readUnencrypted(privateKeyBuffer, publicKey);
        } else {
            logger.info("Keypair is encrypted with: " + cipherName + ", " + kdfName + ", " + kdfOptions);
            throw new IOException("Cannot read encrypted keypair with " + cipherName + " yet.");
        }
    }

    private PublicKey readPublicKey(final PlainBuffer plainBuffer) throws Buffer.BufferException, GeneralSecurityException {
        return KeyType.fromString(plainBuffer.readString()).readPubKeyFromBuffer(plainBuffer);
    }

    private String readKeyFile(final BufferedReader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line = reader.readLine();
        while (!line.startsWith(END)) {
            sb.append(line);
            line = reader.readLine();
        }
        return sb.toString();
    }

    private boolean checkHeader(final BufferedReader reader) throws IOException {
        String line = reader.readLine();
        while (line != null && !line.startsWith(BEGIN)) {
            line = reader.readLine();
        }
        line = line.substring(BEGIN.length());
        return line.startsWith(OPENSSH_PRIVATE_KEY);
    }

    private KeyPair readUnencrypted(final PlainBuffer keyBuffer, final PublicKey publicKey) throws IOException, GeneralSecurityException {
        int privKeyListSize = keyBuffer.available();
        if (privKeyListSize % 8 != 0) {
            throw new IOException("The private key section must be a multiple of the block size (8)");
        }
        int checkInt1 = keyBuffer.readUInt32AsInt(); // uint32 checkint1
        int checkInt2 = keyBuffer.readUInt32AsInt(); // uint32 checkint2
        if (checkInt1 != checkInt2) {
            throw new IOException("The checkInts differed, the key was not correctly decoded.");
        }
        // The private key section contains both the public key and the private key
        String keyType = keyBuffer.readString(); // string keytype
        logger.info("Read key type: {}", keyType);

        byte[] pubKey = keyBuffer.readBytes(); // string publickey (again...)
        keyBuffer.readUInt32();
        byte[] privKey = new byte[32];
        keyBuffer.readRawBytes(privKey); // string privatekey
        keyBuffer.readRawBytes(new byte[32]); // string publickey (again...)
        String comment = keyBuffer.readString(); // string comment
        byte[] padding = new byte[keyBuffer.available()];
        keyBuffer.readRawBytes(padding); // char[] padding
        for (int i = 0; i < padding.length; i++) {
            if ((int) padding[i] != i + 1) {
                throw new IOException("Padding of key format contained wrong byte at position: " + i);
            }
        }
        return new KeyPair(publicKey, new EdDSAPrivateKey(new EdDSAPrivateKeySpec(privKey, EdDSANamedCurveTable.getByName("Ed25519"))));
    }
}
