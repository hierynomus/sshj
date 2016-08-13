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

import net.schmizz.sshj.common.Base64;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.transport.cipher.AES128CBC;
import net.schmizz.sshj.transport.cipher.AES192CBC;
import net.schmizz.sshj.transport.cipher.AES256CBC;
import net.schmizz.sshj.transport.cipher.Cipher;
import net.schmizz.sshj.transport.cipher.NoneCipher;
import net.schmizz.sshj.transport.cipher.TripleDESCBC;
import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.digest.MD5;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.password.PrivateKeyFileResource;
import net.schmizz.sshj.userauth.password.PrivateKeyReaderResource;
import net.schmizz.sshj.userauth.password.PrivateKeyStringResource;
import net.schmizz.sshj.userauth.password.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.EOFException;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

/** Represents a PKCS8-encoded key file. This is the format used by OpenSSH and OpenSSL. */
public class PKCS8KeyFile
        implements FileKeyProvider {

    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<FileKeyProvider> {

        @Override
        public FileKeyProvider create() {
            return new PKCS8KeyFile();
        }

        @Override
        public String getName() {
            return "PKCS8";
        }
    }

    protected final Logger log = LoggerFactory.getLogger(getClass());
    protected PasswordFinder pwdf;
    protected Resource<?> resource;
    protected KeyPair kp;

    protected KeyType type;

    protected char[] passphrase; // for blanking out

    @Override
    public PrivateKey getPrivate()
            throws IOException {
        return kp != null ? kp.getPrivate() : (kp = readKeyPair()).getPrivate();
    }

    @Override
    public PublicKey getPublic()
            throws IOException {
        return kp != null ? kp.getPublic() : (kp = readKeyPair()).getPublic();
    }

    @Override
    public KeyType getType()
            throws IOException {
        return type != null ? type : (type = KeyType.fromKey(getPublic()));
    }

    @Override
    public void init(Reader location) {
        assert location != null;
        resource = new PrivateKeyReaderResource(location);
    }

    @Override
    public void init(Reader location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(File location) {
        assert location != null;
        resource = new PrivateKeyFileResource(location.getAbsoluteFile());
    }

    @Override
    public void init(File location, PasswordFinder pwdf) {
        init(location);
        this.pwdf = pwdf;
    }

    @Override
    public void init(String privateKey, String publicKey) {
        assert privateKey != null;
        assert publicKey == null;
        resource = new PrivateKeyStringResource(privateKey);
    }

    @Override
    public void init(String privateKey, String publicKey, PasswordFinder pwdf) {
        init(privateKey, publicKey);
        this.pwdf = pwdf;
    }

    protected KeyPair readKeyPair()
            throws IOException {
	BufferedReader reader = new BufferedReader(resource.getReader());
	try {
	    String type = null;
	    String line = null;
	    Cipher cipher = new NoneCipher();
	    StringBuffer sb = new StringBuffer();
	    byte[] iv = new byte[0]; // salt
	    while ((line = reader.readLine()) != null) {
		if (line.startsWith("-----BEGIN ") && line.endsWith(" PRIVATE KEY-----")) {
		    int end = line.length() - 17;
		    if (end > 11) {
			type = line.substring(11, line.length() - 17);
		    } else {
			type = "UNKNOWN";
		    }
		} else if (line.startsWith("-----END")) {
		    break;
		} else if (type != null) {
		    if (line.startsWith("Proc-Type: ")) {
			if (!"4,ENCRYPTED".equals(line.substring(11))) {
			    throw new IOException("Unrecognized Proc-Type: " + line.substring(11));
			}
		    } else if (line.startsWith("DEK-Info: ")) {
			int ptr = line.indexOf(",");
			if (ptr == -1) {
			    throw new IOException("Unrecognized DEK-Info: " + line.substring(10));
			} else {
			    String algorithm = line.substring(10,ptr);
			    if ("DES-EDE3-CBC".equals(algorithm)) {
				cipher = new TripleDESCBC();
				iv = DatatypeConverter.parseHexBinary(line.substring(ptr+1));
			    } else if ("AES-128-CBC".equals(algorithm)) {
				cipher = new AES128CBC();
				iv = DatatypeConverter.parseHexBinary(line.substring(ptr+1));
			    } else if ("AES-192-CBC".equals(algorithm)) {
				cipher = new AES192CBC();
				iv = Base64.decode(line.substring(ptr+1));
			    } else if ("AES-256-CBC".equals(algorithm)) {
				cipher = new AES256CBC();
				iv = Base64.decode(line.substring(ptr+1));
			    } else {
				throw new IOException("Not a supported algorithm: " + algorithm);
			    }
			}
		    } else if (line.length() > 0) {
			sb.append(line);
		    }
		}
	    }

	    byte[] data = Base64.decode(sb.toString());
	    if (pwdf != null) {
		boolean decrypted = false;
		do {
		    CharBuffer cb = CharBuffer.wrap(pwdf.reqPassword(resource));
		    ByteBuffer bb = IOUtils.UTF8.encode(cb);
		    byte[] passphrase = Arrays.copyOfRange(bb.array(), bb.position(), bb.limit());
		    Arrays.fill(cb.array(), '\u0000');
		    Arrays.fill(bb.array(), (byte)0);
		    byte[] key = new byte[cipher.getBlockSize()];
		    iv = Arrays.copyOfRange(iv, 0, cipher.getIVSize());
		    Digest md5 = new MD5();
		    md5.init();
		    int hsize = md5.getBlockSize();
		    byte[] hn = new byte[key.length / hsize * hsize + (key.length % hsize == 0 ? 0 : hsize)];
		    byte[] tmp = null;
                    for (int i=0; i + hsize <= hn.length;) {
                        if (tmp != null) {
                           md5.update(tmp, 0, tmp.length);
                        }
                        md5.update(passphrase, 0, passphrase.length);
                        md5.update(iv, 0, iv.length > 8 ? 8 : iv.length);
                        tmp = md5.digest();
                        System.arraycopy(tmp, 0, hn, i, tmp.length);
                        i += tmp.length;
                    }
		    Arrays.fill(passphrase, (byte)0);
                    System.arraycopy(hn, 0, key, 0, key.length);
		    cipher.init(Cipher.Mode.Decrypt, key, iv);
		    Arrays.fill(key, (byte)0);
		    cipher.update(data, 0, data.length);
		    decrypted = 0x30 == data[0];
		} while (!decrypted && pwdf.shouldRetry(resource));
	    }
	    if (0x30 != data[0]) {
		throw new IOException("Failed to decrypt key");
	    }

	    ASN1Data asn = new ASN1Data(data);
	    if ("RSA".equals(type)) {
		KeyFactory factory = KeyFactory.getInstance("RSA");
		asn.readNext();
		BigInteger modulus = asn.readNext();
		BigInteger pubExp = asn.readNext();
		BigInteger prvExp = asn.readNext();
		PublicKey pubKey = factory.generatePublic(new RSAPublicKeySpec(modulus, pubExp));
		PrivateKey prvKey = factory.generatePrivate(new RSAPrivateKeySpec(modulus, prvExp));
		return new KeyPair(pubKey, prvKey);
	    } else if ("DSA".equals(type)) {
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
	    } else {
		throw new IOException("Unrecognized key type: " + type);
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
        return "PKCS8KeyFile{resource=" + resource + "}";
    }

    class ASN1Data {
        private byte[] buff;
	private int index, length;

	ASN1Data(byte[] buff) throws IOException {
	    this.buff = buff;
	    index = 0;
	    if (buff[index++] != (byte)0x30) {
		throw new IOException("Not ASN.1 data");
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
		throw new IOException("Length mismatch: " + buff.length + " != " + (index + length));
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
