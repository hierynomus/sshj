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

import com.hierynomus.sshj.common.KeyAlgorithm;
import com.hierynomus.sshj.common.KeyDecryptionFailedException;
import com.hierynomus.sshj.transport.cipher.BlockCiphers;
import com.hierynomus.sshj.transport.cipher.ChachaPolyCiphers;
import com.hierynomus.sshj.transport.cipher.GcmCiphers;
import com.hierynomus.sshj.userauth.keyprovider.bcrypt.BCrypt;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.common.Buffer.PlainBuffer;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.userauth.keyprovider.BaseFileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.EncryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Reads a key file in the new OpenSSH format.
 * The format is described in the following document: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
 */
public class OpenSSHKeyV1KeyFile extends BaseFileKeyProvider {
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes();
    public static final String OPENSSH_PRIVATE_KEY = "OPENSSH PRIVATE KEY-----";
    public static final String BCRYPT = "bcrypt";

    private static final String NONE_CIPHER = "none";

    private static final Map<String, Factory.Named<Cipher>> SUPPORTED_CIPHERS = new HashMap<>();

    static {
        SUPPORTED_CIPHERS.put(BlockCiphers.TripleDESCBC().getName(), BlockCiphers.TripleDESCBC());
        SUPPORTED_CIPHERS.put(BlockCiphers.AES128CBC().getName(), BlockCiphers.AES128CBC());
        SUPPORTED_CIPHERS.put(BlockCiphers.AES192CBC().getName(), BlockCiphers.AES192CBC());
        SUPPORTED_CIPHERS.put(BlockCiphers.AES256CBC().getName(), BlockCiphers.AES256CBC());
        SUPPORTED_CIPHERS.put(BlockCiphers.AES128CTR().getName(), BlockCiphers.AES128CTR());
        SUPPORTED_CIPHERS.put(BlockCiphers.AES192CTR().getName(), BlockCiphers.AES192CTR());
        SUPPORTED_CIPHERS.put(BlockCiphers.AES256CTR().getName(), BlockCiphers.AES256CTR());
        SUPPORTED_CIPHERS.put(GcmCiphers.AES256GCM().getName(), GcmCiphers.AES256GCM());
        SUPPORTED_CIPHERS.put(GcmCiphers.AES128GCM().getName(), GcmCiphers.AES128GCM());
        SUPPORTED_CIPHERS.put(ChachaPolyCiphers.CHACHA_POLY_OPENSSH().getName(), ChachaPolyCiphers.CHACHA_POLY_OPENSSH());
    }

    private PublicKey pubKey;

    @Override
    public PublicKey getPublic()
            throws IOException {
        return pubKey != null ? pubKey : super.getPublic();
    }

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

    protected final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public void init(File location, PasswordFinder pwdf) {
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
                log.warn("Error reading public key file: {}", e.toString());
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
                log.warn("Error reading public key file: {}", e.toString());
            }
        }
        super.init(privateKey, null, pwdf);
    }

    @Override
    protected KeyPair readKeyPair() throws IOException {
        final BufferedReader reader = new BufferedReader(resource.getReader());
        try {
            if (checkHeader(reader)) {
                final String encodedPrivateKey = readEncodedKey(reader);
                byte[] decodedPrivateKey = Base64Decoder.decode(encodedPrivateKey);
                final PlainBuffer bufferedPrivateKey = new PlainBuffer(decodedPrivateKey);
                return readDecodedKeyPair(bufferedPrivateKey);
            } else {
                final String message = String.format("File header not found [%s%s]", BEGIN, OPENSSH_PRIVATE_KEY);
                throw new IOException(message);
            }
        } catch (final GeneralSecurityException e) {
            throw new SSHRuntimeException("Read OpenSSH Version 1 Key failed", e);
        } catch (Base64DecodingException e) {
            throw new SSHRuntimeException("Private Key decoding failed", e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }

    private void initPubKey(Reader publicKey) throws IOException {
        OpenSSHKeyFileUtil.ParsedPubKey parsed = OpenSSHKeyFileUtil.initPubKey(publicKey);
        type = parsed.getType();
        pubKey = parsed.getPubKey();
    }

    private KeyPair readDecodedKeyPair(final PlainBuffer keyBuffer) throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[AUTH_MAGIC.length];
        keyBuffer.readRawBytes(bytes); // byte[] AUTH_MAGIC
        if (!ByteArrayUtils.equals(bytes, 0, AUTH_MAGIC, 0, AUTH_MAGIC.length)) {
            throw new IOException("This key does not contain the 'openssh-key-v1' format magic header");
        }

        String cipherName = keyBuffer.readString(); // string ciphername
        String kdfName = keyBuffer.readString(); // string kdfname
        byte[] kdfOptions = keyBuffer.readBytes(); // string kdfoptions

        int nrKeys = keyBuffer.readUInt32AsInt(); // int number of keys N; Should be 1
        if (nrKeys != 1) {
            final String message = String.format("OpenSSH Private Key number of keys not supported [%d]", nrKeys);
            throw new IOException(message);
        }
        PublicKey publicKey = pubKey;
        if (publicKey == null) {
            publicKey = readPublicKey(new PlainBuffer(keyBuffer.readBytes()));
        } else {
            keyBuffer.readBytes();
        }

        final byte[] privateKeyEncoded = keyBuffer.readBytes();
        final PlainBuffer privateKeyBuffer = new PlainBuffer(privateKeyEncoded);

        if (NONE_CIPHER.equals(cipherName)) {
            return readUnencrypted(privateKeyBuffer, publicKey);
        } else {
            final byte[] encryptedPrivateKey = readEncryptedPrivateKey(privateKeyEncoded, keyBuffer);
            while (true) {
                final byte[] encrypted = encryptedPrivateKey.clone();
                try {
                    final PlainBuffer decrypted = decryptPrivateKey(encrypted, privateKeyEncoded.length, cipherName, kdfName, kdfOptions);
                    return readUnencrypted(decrypted, publicKey);
                } catch (KeyDecryptionFailedException e) {
                    if (pwdf == null || !pwdf.shouldRetry(resource))
                        throw e;
                }
            }
        }
    }

    private byte[] readEncryptedPrivateKey(final byte[] privateKeyEncoded, final PlainBuffer inputBuffer) throws Buffer.BufferException {
        final byte[] encryptedPrivateKey;

        final int bufferRemaining = inputBuffer.available();
        if (bufferRemaining == 0) {
            encryptedPrivateKey = privateKeyEncoded;
        } else {
            // Read Authentication Tag for AES-GCM or ChaCha20-Poly1305
            final byte[] authenticationTag = new byte[bufferRemaining];
            inputBuffer.readRawBytes(authenticationTag);

            final int encryptedBufferLength = privateKeyEncoded.length + authenticationTag.length;
            final PlainBuffer encryptedBuffer = new PlainBuffer(encryptedBufferLength);
            encryptedBuffer.putRawBytes(privateKeyEncoded);
            encryptedBuffer.putRawBytes(authenticationTag);

            encryptedPrivateKey = new byte[encryptedBufferLength];
            encryptedBuffer.readRawBytes(encryptedPrivateKey);
        }

        return encryptedPrivateKey;
    }

    private PlainBuffer decryptPrivateKey(final byte[] privateKey, final int privateKeyLength, final String cipherName, final String kdfName, final byte[] kdfOptions) throws IOException {
        try {
            final Cipher cipher = createCipher(cipherName);
            initializeCipher(kdfName, kdfOptions, cipher);
            cipher.update(privateKey, 0, privateKeyLength);
        } catch (final SSHRuntimeException e) {
            final String message = String.format("OpenSSH Private Key decryption failed with cipher [%s]", cipherName);
            throw new KeyDecryptionFailedException(new EncryptionException(message, e));
        }
        final PlainBuffer decryptedPrivateKey = new PlainBuffer(privateKeyLength);
        decryptedPrivateKey.putRawBytes(privateKey, 0, privateKeyLength);
        return decryptedPrivateKey;
    }

    private void initializeCipher(final String kdfName, final byte[] kdfOptions, final Cipher cipher) throws Buffer.BufferException {
        if (kdfName.equals(BCRYPT)) {
            final PlainBuffer bufferedOptions = new PlainBuffer(kdfOptions);
            byte[] passphrase = new byte[0];
            if (pwdf != null) {
                final CharBuffer charBuffer = CharBuffer.wrap(pwdf.reqPassword(null));
                final ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
                passphrase = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
                Arrays.fill(charBuffer.array(), '\u0000');
                Arrays.fill(byteBuffer.array(), (byte) 0);
            }

            final int ivSize = cipher.getIVSize();
            final int blockSize = cipher.getBlockSize();
            final int parameterSize = ivSize + blockSize;
            final byte[] keyIvParameters = new byte[parameterSize];

            final byte[] salt = bufferedOptions.readBytes();
            final int iterations = bufferedOptions.readUInt32AsInt();
            new BCrypt().pbkdf(passphrase, salt, iterations, keyIvParameters);
            Arrays.fill(passphrase, (byte) 0);

            final byte[] key = Arrays.copyOfRange(keyIvParameters, 0, blockSize);
            final byte[] iv = Arrays.copyOfRange(keyIvParameters, blockSize, parameterSize);

            cipher.init(Cipher.Mode.Decrypt, key, iv);
        } else {
            final String message = String.format("OpenSSH Private Key encryption KDF not supported [%s]", kdfName);
            throw new IllegalStateException(message);
        }
    }

    private Cipher createCipher(final String cipherName) {
        final Cipher cipher;

        if (SUPPORTED_CIPHERS.containsKey(cipherName)) {
            final Factory.Named<Cipher> cipherFactory = SUPPORTED_CIPHERS.get(cipherName);
            cipher = cipherFactory.create();
        } else {
            final String message = String.format("OpenSSH Key encryption cipher not supported [%s]", cipherName);
            throw new IllegalStateException(message);
        }

        return cipher;
    }

    private PublicKey readPublicKey(final PlainBuffer plainBuffer) throws Buffer.BufferException, GeneralSecurityException {
        return KeyType.fromString(plainBuffer.readString()).readPubKeyFromBuffer(plainBuffer);
    }

    private String readEncodedKey(final BufferedReader reader) throws IOException {
        final StringBuilder builder = new StringBuilder();

        boolean footerFound = false;
        String line = reader.readLine();
        while (line != null) {
            if (line.startsWith(END)) {
                footerFound = true;
                break;
            }
            builder.append(line);
            line = reader.readLine();
        }

        if (footerFound) {
            return builder.toString();
        } else {
            final String message = String.format("File footer not found [%s%s]", END, OPENSSH_PRIVATE_KEY);
            throw new IOException(message);
        }
    }

    private boolean checkHeader(final BufferedReader reader) throws IOException {
        String line = reader.readLine();
        while (line != null && !line.startsWith(BEGIN)) {
            line = reader.readLine();
        }
        if (line == null) {
            return false;
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
            throw new KeyDecryptionFailedException(new EncryptionException("OpenSSH Private Key integer comparison failed"));
        }
        // The private key section contains both the public key and the private key
        String keyType = keyBuffer.readString(); // string keytype
        KeyType kt = KeyType.fromString(keyType);

        KeyPair kp;
        switch (kt) {
            case ED25519:
                keyBuffer.readBytes(); // string publickey (again...)
                keyBuffer.readUInt32(); // length of privatekey+publickey
                byte[] privKey = new byte[32];
                keyBuffer.readRawBytes(privKey); // string privatekey
                keyBuffer.readRawBytes(new byte[32]); // string publickey (again...)
                kp = new KeyPair(publicKey, new EdDSAPrivateKey(new EdDSAPrivateKeySpec(privKey, EdDSANamedCurveTable.getByName("Ed25519"))));
                break;
            case RSA:
                final RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = readRsaPrivateKeySpec(keyBuffer);
                final PrivateKey privateKey = SecurityUtils.getKeyFactory(KeyAlgorithm.RSA).generatePrivate(rsaPrivateCrtKeySpec);
                kp = new KeyPair(publicKey, privateKey);
                break;
            case ECDSA256:
                kp = new KeyPair(publicKey, createECDSAPrivateKey(kt, keyBuffer, "P-256"));
                break;
            case ECDSA384:
                kp = new KeyPair(publicKey, createECDSAPrivateKey(kt, keyBuffer, "P-384"));
                break;
            case ECDSA521:
                kp = new KeyPair(publicKey, createECDSAPrivateKey(kt, keyBuffer, "P-521"));
                break;

            default:
                throw new IOException("Cannot decode keytype " + keyType + " in openssh-key-v1 files (yet).");
        }
        keyBuffer.readString(); // string comment
        byte[] padding = new byte[keyBuffer.available()];
        keyBuffer.readRawBytes(padding); // char[] padding
        for (int i = 0; i < padding.length; i++) {
            if ((int) padding[i] != i + 1) {
                throw new IOException("Padding of key format contained wrong byte at position: " + i);
            }
        }
        return kp;
    }

    private PrivateKey createECDSAPrivateKey(KeyType kt, PlainBuffer buffer, String name) throws GeneralSecurityException, Buffer.BufferException {
        kt.readPubKeyFromBuffer(buffer); // Public key
        BigInteger s = new BigInteger(1, buffer.readBytes());
        X9ECParameters ecParams = NISTNamedCurves.getByName(name);
        ECNamedCurveSpec ecCurveSpec = new ECNamedCurveSpec(name, ecParams.getCurve(), ecParams.getG(), ecParams.getN());
        ECPrivateKeySpec pks = new ECPrivateKeySpec(s, ecCurveSpec);
        return SecurityUtils.getKeyFactory(KeyAlgorithm.ECDSA).generatePrivate(pks);
    }

    /**
     * Read RSA Private CRT Key Spec according to OpenSSH sshkey_private_deserialize in sshkey.c
     *
     * @param buffer Buffer
     * @return RSA Private CRT Key Specification
     * @throws Buffer.BufferException Thrown on failure to read from buffer
     */
    private RSAPrivateCrtKeySpec readRsaPrivateKeySpec(final PlainBuffer buffer) throws Buffer.BufferException {
        final BigInteger modulus = buffer.readMPInt();
        final BigInteger publicExponent = buffer.readMPInt();
        final BigInteger privateExponent = buffer.readMPInt();
        final BigInteger crtCoefficient = buffer.readMPInt(); // iqmp (q^-1 mod p)
        final BigInteger primeP = buffer.readMPInt();
        final BigInteger primeQ = buffer.readMPInt();

        // Calculate Prime Exponent P and Prime Exponent Q according to RFC 8017 Section 3.2
        final BigInteger primeExponentP = privateExponent.remainder(primeP.subtract(BigInteger.ONE));
        final BigInteger primeExponentQ = privateExponent.remainder(primeQ.subtract(BigInteger.ONE));
        return new RSAPrivateCrtKeySpec(
                modulus,
                publicExponent,
                privateExponent,
                primeP,
                primeQ,
                primeExponentP,
                primeExponentQ,
                crtCoefficient
        );
    }
}
