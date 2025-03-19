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

import com.hierynomus.sshj.common.KeyAlgorithm;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.userauth.password.PasswordUtils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * <h2>Sample PuTTY file format</h2>
 *
 * <pre>
 * PuTTY-User-Key-File-2: ssh-rsa
 * Encryption: none
 * Comment: rsa-key-20080514
 * Public-Lines: 4
 * AAAAB3NzaC1yc2EAAAABJQAAAIEAiPVUpONjGeVrwgRPOqy3Ym6kF/f8bltnmjA2
 * BMdAtaOpiD8A2ooqtLS5zWYuc0xkW0ogoKvORN+RF4JI+uNUlkxWxnzJM9JLpnvA
 * HrMoVFaQ0cgDMIHtE1Ob1cGAhlNInPCRnGNJpBNcJ/OJye3yt7WqHP4SPCCLb6nL
 * nmBUrLM=
 * Private-Lines: 8
 * AAAAgGtYgJzpktzyFjBIkSAmgeVdozVhgKmF6WsDMUID9HKwtU8cn83h6h7ug8qA
 * hUWcvVxO201/vViTjWVz9ALph3uMnpJiuQaaNYIGztGJBRsBwmQW9738pUXcsUXZ
 * 79KJP01oHn6Wkrgk26DIOsz04QOBI6C8RumBO4+F1WdfueM9AAAAQQDmA4hcK8Bx
 * nVtEpcF310mKD3nsbJqARdw5NV9kCxPnEsmy7Sy1L4Ob/nTIrynbc3MA9HQVJkUz
 * 7V0va5Pjm/T7AAAAQQCYbnG0UEekwk0LG1Hkxh1OrKMxCw2KWMN8ac3L0LVBg/Tk
 * 8EnB2oT45GGeJaw7KzdoOMFZz0iXLsVLNUjNn2mpAAAAQQCN6SEfWqiNzyc/w5n/
 * lFVDHExfVUJp0wXv+kzZzylnw4fs00lC3k4PZDSsb+jYCMesnfJjhDgkUA0XPyo8
 * Emdk
 * Private-MAC: 50c45751d18d74c00fca395deb7b7695e3ed6f77
 * </pre>
 *
 * @version $Id:$
 */
public class PuTTYKeyFile extends BaseFileKeyProvider {

    public static class Factory implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new PuTTYKeyFile();
        }

        @Override
        public String getName() {
            return "PuTTY";
        }
    }

    private static final String KEY_DERIVATION_HEADER = "Key-Derivation";

    private Integer keyFileVersion;
    private byte[] privateKey;
    private byte[] publicKey;
    private byte[] verifyHmac; // only used by v3 keys

    /**
     * Key type
     */
    @Override
    public KeyType getType() throws IOException {
        String headerName = String.format("PuTTY-User-Key-File-%d", this.keyFileVersion);
        return KeyType.fromString(headers.get(headerName));
    }

    public boolean isEncrypted() throws IOException {
        // Currently, the only supported encryption types are "aes256-cbc" and "none".
        String encryption = headers.get("Encryption");
        if ("none".equals(encryption)) {
            return false;
        }
        if ("aes256-cbc".equals(encryption)) {
            return true;
        }
        throw new IOException(String.format("Unsupported encryption: %s", encryption));
    }

    private final Map<String, String> payload = new HashMap<>();

    /**
     * For each line that looks like "Xyz: vvv", it will be stored in this map.
     */
    private final Map<String, String> headers = new HashMap<>();

    protected KeyPair readKeyPair() throws IOException {
        this.parseKeyPair();
        final Buffer.PlainBuffer publicKeyReader = new Buffer.PlainBuffer(publicKey);
        final Buffer.PlainBuffer privateKeyReader = new Buffer.PlainBuffer(privateKey);
        final KeyType keyType = this.getType();
        publicKeyReader.readBytes(); // The first part of the payload is a human-readable key format name.
        if (KeyType.RSA.equals(keyType)) {
            // public key exponent
            BigInteger e = publicKeyReader.readMPInt();
            // modulus
            BigInteger n = publicKeyReader.readMPInt();

            // private key exponent
            BigInteger d = privateKeyReader.readMPInt();

            final KeyFactory factory;
            try {
                factory = KeyFactory.getInstance(KeyAlgorithm.RSA);
            } catch (NoSuchAlgorithmException s) {
                throw new IOException(s.getMessage(), s);
            }
            try {
                return new KeyPair(factory.generatePublic(new RSAPublicKeySpec(n, e)),
                        factory.generatePrivate(new RSAPrivateKeySpec(n, d)));
            } catch (InvalidKeySpecException i) {
                throw new IOException(i.getMessage(), i);
            }
        }
        if (KeyType.DSA.equals(keyType)) {
            BigInteger p = publicKeyReader.readMPInt();
            BigInteger q = publicKeyReader.readMPInt();
            BigInteger g = publicKeyReader.readMPInt();
            BigInteger y = publicKeyReader.readMPInt();

            // Private exponent from the private key
            BigInteger x = privateKeyReader.readMPInt();

            final KeyFactory factory;
            try {
                factory = KeyFactory.getInstance(KeyAlgorithm.DSA);
            } catch (NoSuchAlgorithmException s) {
                throw new IOException(s.getMessage(), s);
            }
            try {
                return new KeyPair(factory.generatePublic(new DSAPublicKeySpec(y, p, q, g)),
                        factory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g)));
            } catch (InvalidKeySpecException e) {
                throw new IOException(e.getMessage(), e);
            }
        }
        if (KeyType.ED25519.equals(keyType)) {
            try {
                final byte[] publicKeyEncoded = publicKeyReader.readBytes();
                final PublicKey edPublicKey = Ed25519KeyFactory.getPublicKey(publicKeyEncoded);

                final byte[] privateKeyEncoded = privateKeyReader.readBytes();
                final PrivateKey edPrivateKey = Ed25519KeyFactory.getPrivateKey(privateKeyEncoded);

                return new KeyPair(edPublicKey, edPrivateKey);
            } catch (final GeneralSecurityException e) {
                throw new IOException("Reading Ed25519 Keys failed", e);
            }
        }
        final ECDSACurve ecdsaCurve;
        switch (keyType) {
            case ECDSA256:
                ecdsaCurve = ECDSACurve.SECP256R1;
                break;
            case ECDSA384:
                ecdsaCurve = ECDSACurve.SECP384R1;
                break;
            case ECDSA521:
                ecdsaCurve = ECDSACurve.SECP521R1;
                break;
            default:
                ecdsaCurve = null;
                break;
        }
        if (ecdsaCurve != null) {
            final BigInteger s = new BigInteger(1, privateKeyReader.readBytes());

            try {
                final PrivateKey privateKey = ECDSAKeyFactory.getPrivateKey(s, ecdsaCurve);
                return new KeyPair(keyType.readPubKeyFromBuffer(publicKeyReader), privateKey);
            } catch (GeneralSecurityException e) {
                throw new IOException(e.getMessage(), e);
            }
        }
        throw new IOException(String.format("Unknown key type %s", this.getType()));
    }

    protected void parseKeyPair() throws IOException {
        this.keyFileVersion = null;
        // Parse the text into headers and payloads
        try (BufferedReader r = new BufferedReader(resource.getReader())) {
            String headerName = null;
            String line;
            while ((line = r.readLine()) != null) {
                int idx = line.indexOf(": ");
                if (idx > 0) {
                    headerName = line.substring(0, idx);
                    headers.put(headerName, line.substring(idx + 2));
                    if (headerName.startsWith("PuTTY-User-Key-File-")) {
                        this.keyFileVersion = Integer.parseInt(headerName.substring(20));
                    }
                } else {
                    String s = payload.get(headerName);
                    if (s == null) {
                        s = line;
                    } else {
                        // Append to previous line
                        s += line;
                    }
                    // Save payload
                    payload.put(headerName, s);
                }
            }
        }
        if (this.keyFileVersion == null) {
            throw new IOException("Invalid key file format: missing \"PuTTY-User-Key-File-?\" entry");
        }
        try {
            // Retrieve keys from payload
            publicKey = Base64Decoder.decode(payload.get("Public-Lines"));
            if (this.isEncrypted()) {
                final char[] passphrase;
                if (pwdf != null) {
                    passphrase = pwdf.reqPassword(resource);
                } else {
                    passphrase = "".toCharArray();
                }
                try {
                    privateKey = this.decrypt(Base64Decoder.decode(payload.get("Private-Lines")), passphrase);
                    Mac mac;
                    if (this.keyFileVersion <= 2) {
                        mac = this.prepareVerifyMacV2(passphrase);
                    } else {
                        mac = this.prepareVerifyMacV3();
                    }
                    this.verify(mac);
                } finally {
                    PasswordUtils.blankOut(passphrase);
                }
            } else {
                privateKey = Base64Decoder.decode(payload.get("Private-Lines"));
            }
        }
        catch (Base64DecodingException e) {
            throw new IOException("PuTTY key decoding failed", e);
        }
    }

    /**
     * Initialize Java Cipher for decryption using Secret Key derived from passphrase according to PuTTY Key Version
     */
    private void initCipher(final char[] passphrase, final Cipher cipher) throws InvalidAlgorithmParameterException, InvalidKeyException {
        final String keyDerivationHeader = headers.get(KEY_DERIVATION_HEADER);

        final SecretKey secretKey;
        final IvParameterSpec ivParameterSpec;

        if (keyDerivationHeader == null) {
            // Key Version 1 and 2 with historical key derivation
            final PuTTYSecretKeyDerivationFunction keyDerivationFunction = new V1PuTTYSecretKeyDerivationFunction();
            secretKey = keyDerivationFunction.deriveSecretKey(passphrase);
            ivParameterSpec = new IvParameterSpec(new byte[16]);
        } else {
            // Key Version 3 with Argon2 key derivation
            final PuTTYSecretKeyDerivationFunction keyDerivationFunction = new V3PuTTYSecretKeyDerivationFunction(headers);
            final SecretKey derivedSecretKey = keyDerivationFunction.deriveSecretKey(passphrase);
            final byte[] derivedSecretKeyEncoded = derivedSecretKey.getEncoded();

            // Set Secret Key from first 32 bytes
            final byte[] secretKeyEncoded = new byte[32];
            System.arraycopy(derivedSecretKeyEncoded, 0, secretKeyEncoded, 0, secretKeyEncoded.length);
            secretKey = new SecretKeySpec(secretKeyEncoded, derivedSecretKey.getAlgorithm());

            // Set IV from next 16 bytes
            final byte[] iv = new byte[16];
            System.arraycopy(derivedSecretKeyEncoded, secretKeyEncoded.length, iv, 0, iv.length);
            ivParameterSpec = new IvParameterSpec(iv);

            // Set HMAC Tag from next 32 bytes
            final byte[] tag = new byte[32];
            final int tagSourcePosition = secretKeyEncoded.length + iv.length;
            System.arraycopy(derivedSecretKeyEncoded, tagSourcePosition, tag, 0, tag.length);
            verifyHmac = tag;
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
    }

    /**
     * Verify the MAC (only required for v1/v2 keys. v3 keys are automatically
     * verified as part of the decryption process.
     */
    private void verify(final Mac mac) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(256);
        final DataOutputStream data = new DataOutputStream(out);
        // name of algorithm
        String keyType = this.getType().toString();
        data.writeInt(keyType.length());
        data.writeBytes(keyType);

        data.writeInt(headers.get("Encryption").length());
        data.writeBytes(headers.get("Encryption"));

        data.writeInt(headers.get("Comment").length());
        data.writeBytes(headers.get("Comment"));

        data.writeInt(publicKey.length);
        data.write(publicKey);

        data.writeInt(privateKey.length);
        data.write(privateKey);

        final String encoded = ByteArrayUtils.toHex(mac.doFinal(out.toByteArray()));
        final String reference = headers.get("Private-MAC");
        if (!encoded.equals(reference)) {
            throw new IOException("Invalid passphrase");
        }
    }

    private Mac prepareVerifyMacV2(final char[] passphrase) throws IOException {
        // The key to the MAC is itself a SHA-1 hash of (v1/v2 key only):
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update("putty-private-key-file-mac-key".getBytes());
            if (passphrase != null) {
                byte[] encodedPassphrase = PasswordUtils.toByteArray(passphrase);
                digest.update(encodedPassphrase);
                Arrays.fill(encodedPassphrase, (byte) 0);
            }
            final byte[] key = digest.digest();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, 0, 20, mac.getAlgorithm()));
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    private Mac prepareVerifyMacV3() throws IOException {
        // for v3 keys the hMac key is included in the Argon output
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.verifyHmac, 0, 32, mac.getAlgorithm()));
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    /**
     * Decrypt private key
     *
     * @param privateKey the SSH private key to be decrypted
     * @param passphrase To decrypt
     */
    private byte[] decrypt(final byte[] privateKey, final char[] passphrase) throws IOException {
        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            this.initCipher(passphrase, cipher);
            return cipher.doFinal(privateKey);
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    public int getKeyFileVersion() {
        return keyFileVersion;
    }

}
