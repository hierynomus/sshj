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
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
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

    private byte[] privateKey;
    private byte[] publicKey;

    /**
     * Key type
     */
    @Override
    public KeyType getType() throws IOException {
        for (String h : headers.keySet()) {
            if (h.startsWith("PuTTY-User-Key-File-")) {
                return KeyType.fromString(headers.get(h));
            }
        }
        return KeyType.UNKNOWN;
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

    private Map<String, String> payload = new HashMap<String, String>();

    /**
     * For each line that looks like "Xyz: vvv", it will be stored in this map.
     */
    private final Map<String, String> headers = new HashMap<String, String>();

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
            EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("Ed25519");
            EdDSAPublicKeySpec publicSpec = new EdDSAPublicKeySpec(publicKeyReader.readBytes(), ed25519);
            EdDSAPrivateKeySpec privateSpec = new EdDSAPrivateKeySpec(privateKeyReader.readBytes(), ed25519);
            return new KeyPair(new EdDSAPublicKey(publicSpec), new EdDSAPrivateKey(privateSpec));
        }
        final String ecdsaCurve;
        switch (keyType) {
            case ECDSA256:
                ecdsaCurve = "P-256";
                break;
            case ECDSA384:
                ecdsaCurve = "P-384";
                break;
            case ECDSA521:
                ecdsaCurve = "P-521";
                break;
            default:
                ecdsaCurve = null;
                break;
        }
        if (ecdsaCurve != null) {
            BigInteger s = new BigInteger(1, privateKeyReader.readBytes());
            X9ECParameters ecParams = NISTNamedCurves.getByName(ecdsaCurve);
            ECNamedCurveSpec ecCurveSpec = new ECNamedCurveSpec(ecdsaCurve, ecParams.getCurve(), ecParams.getG(),
                    ecParams.getN());
            ECPrivateKeySpec pks = new ECPrivateKeySpec(s, ecCurveSpec);
            try {
                PrivateKey privateKey = SecurityUtils.getKeyFactory(KeyAlgorithm.ECDSA).generatePrivate(pks);
                return new KeyPair(keyType.readPubKeyFromBuffer(publicKeyReader), privateKey);
            } catch (GeneralSecurityException e) {
                throw new IOException(e.getMessage(), e);
            }
        }
        throw new IOException(String.format("Unknown key type %s", this.getType()));
    }

    protected void parseKeyPair() throws IOException {
        BufferedReader r = new BufferedReader(resource.getReader());
        // Parse the text into headers and payloads
        try {
            String headerName = null;
            String line;
            while ((line = r.readLine()) != null) {
                int idx = line.indexOf(": ");
                if (idx > 0) {
                    headerName = line.substring(0, idx);
                    headers.put(headerName, line.substring(idx + 2));
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
        } finally {
            r.close();
        }
        // Retrieve keys from payload
        publicKey = Base64.decode(payload.get("Public-Lines"));
        if (this.isEncrypted()) {
            final char[] passphrase;
            if (pwdf != null) {
                passphrase = pwdf.reqPassword(resource);
            } else {
                passphrase = "".toCharArray();
            }
            try {
                privateKey = this.decrypt(Base64.decode(payload.get("Private-Lines")), new String(passphrase));
                this.verify(new String(passphrase));
            } finally {
                PasswordUtils.blankOut(passphrase);
            }
        } else {
            privateKey = Base64.decode(payload.get("Private-Lines"));
        }
    }

    /**
     * Converts a passphrase into a key, by following the convention that PuTTY
     * uses.
     * <p/>
     * <p/>
     * This is used to decrypt the private key when it's encrypted.
     */
    private byte[] toKey(final String passphrase) throws IOException {
        // The field Key-Derivation has been introduced with Putty v3 key file format
        // The only available formats are "Argon2i" "Argon2d" and "Argon2id"
        String keyDerivation = headers.get("Key-Derivation");
        if (keyDerivation != null) {
            throw new IOException(String.format("Unsupported key derivation function: %s", keyDerivation));
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");

            // The encryption key is derived from the passphrase by means of a succession of
            // SHA-1 hashes.

            // Sequence number 0
            digest.update(new byte[] { 0, 0, 0, 0 });
            digest.update(passphrase.getBytes());
            byte[] key1 = digest.digest();

            // Sequence number 1
            digest.update(new byte[] { 0, 0, 0, 1 });
            digest.update(passphrase.getBytes());
            byte[] key2 = digest.digest();

            byte[] r = new byte[32];
            System.arraycopy(key1, 0, r, 0, 20);
            System.arraycopy(key2, 0, r, 20, 12);

            return r;
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    /**
     * Verify the MAC.
     */
    private void verify(final String passphrase) throws IOException {
        try {
            // The key to the MAC is itself a SHA-1 hash of (v1/v2 key only):
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update("putty-private-key-file-mac-key".getBytes());
            if (passphrase != null) {
                digest.update(passphrase.getBytes());
            }
            final byte[] key = digest.digest();

            final Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, 0, 20, mac.getAlgorithm()));

            final ByteArrayOutputStream out = new ByteArrayOutputStream();
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

            final String encoded = Hex.toHexString(mac.doFinal(out.toByteArray()));
            final String reference = headers.get("Private-MAC");
            if (!encoded.equals(reference)) {
                throw new IOException("Invalid passphrase");
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    /**
     * Decrypt private key
     *
     * @param passphrase To decrypt
     */
    private byte[] decrypt(final byte[] key, final String passphrase) throws IOException {
        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            final byte[] expanded = this.toKey(passphrase);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(expanded, 0, 32, "AES"),
                    new IvParameterSpec(new byte[16])); // initial vector=0
            return cipher.doFinal(key);
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage(), e);
        }
    }
}
