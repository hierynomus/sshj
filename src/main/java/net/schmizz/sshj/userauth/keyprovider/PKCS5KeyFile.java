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

import com.hierynomus.sshj.transport.cipher.BlockCiphers;
import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.ByteArrayUtils;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.transport.cipher.*;
import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.digest.MD5;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 * Represents a PKCS5-encoded key file. This is the format typically used by OpenSSH, OpenSSL, Amazon, etc.
 */
public class PKCS5KeyFile extends BaseFileKeyProvider {

    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new PKCS5KeyFile();
        }

        @Override
        public String getName() {
            return "PKCS5";
        }
    }

    /**
     * Indicates a format issue with PKCS5 data
     */
    public static class FormatException
            extends IOException {

        FormatException(String msg) {
            super(msg);
        }
    }

    /**
     * Indicates a problem decrypting the data
     */
    public static class DecryptException
            extends IOException {

        DecryptException(String msg) {
            super(msg);
        }
    }

    protected byte[] data;

    protected KeyPair readKeyPair()
            throws IOException {

        BufferedReader reader = new BufferedReader(resource.getReader());
        try {
            String line = null;
            Cipher cipher = new NoneCipher();
            StringBuffer sb = new StringBuffer();
            byte[] iv = new byte[0]; // salt
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("-----BEGIN ") && line.endsWith(" PRIVATE KEY-----")) {
                    int end = line.length() - 17;
                    if (end > 11) {
                        String s = line.substring(11, line.length() - 17);
                        if ("RSA".equals(s)) {
                            type = KeyType.RSA;
                        } else if ("DSA".equals(s)) {
                            type = KeyType.DSA;
                        } else if ("DSS".equals(s)) {
                            type = KeyType.DSA;
                        } else {
                            throw new FormatException("Unrecognized PKCS5 key type: " + s);
                        }
                    } else {
                        throw new FormatException("Bad header; possibly PKCS8 format?");
                    }
                } else if (line.startsWith("-----END")) {
                    break;
                } else if (type != null) {
                    if (line.startsWith("Proc-Type: ")) {
                        if (!"4,ENCRYPTED".equals(line.substring(11))) {
                            throw new FormatException("Unrecognized Proc-Type: " + line.substring(11));
                        }
                    } else if (line.startsWith("DEK-Info: ")) {
                        int ptr = line.indexOf(",");
                        if (ptr == -1) {
                            throw new FormatException("Unrecognized DEK-Info: " + line.substring(10));
                        } else {
                            String algorithm = line.substring(10, ptr);
                            if ("DES-EDE3-CBC".equals(algorithm)) {
                                cipher = BlockCiphers.TripleDESCBC().create();
                            } else if ("AES-128-CBC".equals(algorithm)) {
                                cipher = BlockCiphers.AES128CBC().create();
                            } else if ("AES-192-CBC".equals(algorithm)) {
                                cipher = BlockCiphers.AES192CBC().create();
                            } else if ("AES-256-CBC".equals(algorithm)) {
                                cipher = BlockCiphers.AES256CBC().create();
                            } else {
                                throw new FormatException("Not a supported algorithm: " + algorithm);
                            }
                            iv = Arrays.copyOfRange(ByteArrayUtils.parseHex(line.substring(ptr + 1)), 0, cipher.getIVSize());
                        }
                    } else if (line.length() > 0) {
                        sb.append(line);
                    }
                }
            }
            if (type == null) {
                throw new FormatException("PKCS5 header not found");
            }
            ASN1Data asn = new ASN1Data(data = decrypt(Base64.decode(sb.toString()), cipher, iv));
            switch (type) {
                case RSA: {
                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    asn.readNext();
                    BigInteger modulus = asn.readNext();
                    BigInteger pubExp = asn.readNext();
                    BigInteger prvExp = asn.readNext();
                    PublicKey pubKey = factory.generatePublic(new RSAPublicKeySpec(modulus, pubExp));
                    PrivateKey prvKey = factory.generatePrivate(new RSAPrivateKeySpec(modulus, prvExp));
                    return new KeyPair(pubKey, prvKey);
                }
                case DSA: {
                    KeyFactory factory = KeyFactory.getInstance("DSA");
                    asn.readNext();
                    BigInteger p = asn.readNext();
                    BigInteger q = asn.readNext();
                    BigInteger g = asn.readNext();
                    BigInteger pub = asn.readNext();
                    BigInteger prv = asn.readNext();
                    PublicKey pubKey = factory.generatePublic(new DSAPublicKeySpec(pub, p, q, g));
                    PrivateKey prvKey = factory.generatePrivate(new DSAPrivateKeySpec(prv, p, q, g));
                    return new KeyPair(pubKey, prvKey);
                }
                default:
                    throw new IOException("Unrecognized PKCS5 key type: " + type);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        } catch (InvalidKeySpecException e) {
            throw new IOException(e);
        } finally {
            reader.close();
        }
    }

    @Override
    public String toString() {
        return "PKCS5KeyFile{resource=" + resource + "}";
    }

    private byte[] getPassphraseBytes() {
        CharBuffer cb = CharBuffer.wrap(pwdf.reqPassword(resource));
        ByteBuffer bb = IOUtils.UTF8.encode(cb);
        byte[] result = Arrays.copyOfRange(bb.array(), bb.position(), bb.limit());
        Arrays.fill(cb.array(), '\u0000');
        Arrays.fill(bb.array(), (byte) 0);
        return result;
    }

    private byte[] decrypt(byte[] raw, Cipher cipher, byte[] iv) throws DecryptException {
        if (pwdf == null) {
            return raw;
        }
        Digest md5 = new MD5();
        int bsize = cipher.getBlockSize();
        int hsize = md5.getBlockSize();
        int hnlen = bsize / hsize * hsize + (bsize % hsize == 0 ? 0 : hsize);
        do {
            md5.init();
            byte[] hn = new byte[hnlen];
            byte[] tmp = null;
            byte[] passphrase = getPassphraseBytes();
            for (int i = 0; i + hsize <= hn.length; ) {
                if (tmp != null) {
                    md5.update(tmp, 0, tmp.length);
                }
                md5.update(passphrase, 0, passphrase.length);
                md5.update(iv, 0, iv.length > 8 ? 8 : iv.length);
                tmp = md5.digest();
                System.arraycopy(tmp, 0, hn, i, tmp.length);
                i += tmp.length;
            }
            Arrays.fill(passphrase, (byte) 0);
            byte[] key = Arrays.copyOfRange(hn, 0, bsize);
            cipher.init(Cipher.Mode.Decrypt, key, iv);
            Arrays.fill(key, (byte) 0);
            byte[] decrypted = Arrays.copyOf(raw, raw.length);
            cipher.update(decrypted, 0, decrypted.length);
            if (ASN1Data.MAGIC == decrypted[0]) {
                return decrypted;
            }
        } while (pwdf.shouldRetry(resource));
        throw new DecryptException("Decryption failed");
    }

    class ASN1Data {
        static final byte MAGIC = (byte) 0x30;

        private byte[] buff;
        private int index, length;

        ASN1Data(byte[] buff) throws FormatException {
            this.buff = buff;
            index = 0;
            if (buff[index++] != MAGIC) {
                throw new FormatException("Not ASN.1 data");
            }
            length = buff[index++] & 0xff;
            if ((length & 0x80) != 0) {
                int counter = length & 0x7f;
                length = 0;
                while (counter-- > 0) {
                    length = (length << 8) + (buff[index++] & 0xff);
                }
            }
            if ((index + length) > buff.length) {
                throw new FormatException("Length mismatch: " + buff.length + " != " + (index + length));
            }
        }

        BigInteger readNext() throws IOException {
            if (index >= length) {
                throw new EOFException();
            } else if (buff[index++] != 0x02) {
                throw new IOException("Not an int code: " + Integer.toHexString(0xff & buff[index]));
            }
            int length = buff[index++] & 0xff;
            if ((length & 0x80) != 0) {
                int counter = length & 0x7f;
                length = 0;
                while (counter-- > 0) {
                    length = (length << 8) + (buff[index++] & 0xff);
                }
            }
            byte[] sequence = new byte[length];
            System.arraycopy(buff, index, sequence, 0, length);
            index += length;
            return new BigInteger(sequence);
        }
    }
}
