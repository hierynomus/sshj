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
package net.schmizz.sshj.keyprovider;

import com.hierynomus.sshj.common.KeyAlgorithm;
import com.hierynomus.sshj.common.KeyDecryptionFailedException;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.password.Resource;
import net.schmizz.sshj.util.KeyUtil;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PKCS8KeyFileTest {

    static final String modulus = "a19f65e93926d9a2f5b52072db2c38c54e6cf0113d31fa92ff827b0f3bec609c45ea84264c88e64adba11ff093ed48ee0ed297757654b0884ab5a7e28b3c463bc9074b32837a2b69b61d914abf1d74ccd92b20fa44db3b31fb208c0dd44edaeb4ab097118e8ee374b6727b89ad6ce43f1b70c5a437ccebc36d2dad8ae973caad15cd89ae840fdae02cae42d241baef8fda8aa6bbaa54fd507a23338da6f06f61b34fb07d560e63fbce4a39c073e28573c2962cedb292b14b80d1b4e67b0465f2be0e38526232d0a7f88ce91a055fde082038a87ed91f3ef5ff971e30ea6cccf70d38498b186621c08f8fdceb8632992b480bf57fc218e91f2ca5936770fe9469";
    static final String pubExp = "23";
    static final String privExp = "57bcee2e2656eb2c94033d802dd62d726c6705fabad1fd0df86b67600a96431301620d395cbf5871c7af3d3974dfe5c30f5c60d95d7e6e75df69ed6c5a36a9c8aef554b5058b76a719b8478efa08ad1ebf08c8c25fe4b9bc0bfbb9be5d4f60e6213b4ab1c26ad33f5bba7d93e1cd65f65f5a79eb6ebfb32f930a2b0244378b4727acf83b5fb376c38d4abecc5dc3fc399e618e792d4c745d2dbbb9735242e5033129f2985ca3e28fa33cad2afe3e70e1b07ed2b6ec8a3f843fb4bffe3385ad211c6600618488f4ac70397e8eb036b82d811283dc728504cddbe1533c4dd31b1ec99ffa74fd0e3883a9cb3e2315cc1a56f55d38ed40520dd9ec91b4d2dd790d1b";
    static final String KEY_PASSPHRASE = "passphrase";
    static final String INCORRECT_PASSPHRASE = String.class.getSimpleName();

    @Test
    public void testKeys() throws GeneralSecurityException, IOException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        provider.init(new File("src/test/resources/id_rsa"));
        assertEquals(KeyUtil.newRSAPublicKey(modulus, pubExp), provider.getPublic());
        assertEquals(KeyUtil.newRSAPrivateKey(modulus, privExp), provider.getPrivate());
        assertEquals(provider.getType(), KeyType.RSA);
    }

    @Test
    public void testPkcs1Rsa() throws IOException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        provider.init(getFile("pkcs1-rsa"));
        assertEquals(KeyAlgorithm.RSA, provider.getPublic().getAlgorithm());
        assertEquals(KeyAlgorithm.RSA, provider.getPrivate().getAlgorithm());
    }

    @Test
    public void testPkcs1Encrypted() throws IOException, GeneralSecurityException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        provider.init(getFile("pkcs1-rsa-encrypted"), PasswordUtils.createOneOff(KEY_PASSPHRASE.toCharArray()));
        assertEquals(KeyUtil.newRSAPublicKey(modulus, pubExp), provider.getPublic());
        assertEquals(KeyUtil.newRSAPrivateKey(modulus, privExp), provider.getPrivate());
    }

    @Test
    public void testPkcs8Rsa() throws IOException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        provider.init(getFile("pkcs8-rsa-2048"));
        assertEquals(KeyAlgorithm.RSA, provider.getPublic().getAlgorithm());
        assertEquals(KeyAlgorithm.RSA, provider.getPrivate().getAlgorithm());
    }

    @Test
    public void testPkcs8RsaEncrypted() throws IOException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        final PasswordFinder passwordFinder = PasswordUtils.createOneOff(KEY_PASSPHRASE.toCharArray());
        provider.init(getFile("pkcs8-rsa-2048-encrypted"), passwordFinder);
        assertEquals(KeyAlgorithm.RSA, provider.getPublic().getAlgorithm());
        assertEquals(KeyAlgorithm.RSA, provider.getPrivate().getAlgorithm());
    }

    @Test
    public void testPkcs8RsaEncryptedIncorrectPassword() {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        final PasswordFinder passwordFinder = PasswordUtils.createOneOff(INCORRECT_PASSPHRASE.toCharArray());
        provider.init(getFile("pkcs8-rsa-2048-encrypted"), passwordFinder);
        assertThrows(KeyDecryptionFailedException.class, provider::getPrivate);
    }

    @Test
    public void testPkcs8RsaEncryptedRetryPassword() throws IOException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        final PasswordFinder passwordFinder = new PasswordFinder() {
            private boolean retryEnabled = true;

            @Override
            public char[] reqPassword(Resource<?> resource) {
                final char[] password;
                if (retryEnabled) {
                    password = INCORRECT_PASSPHRASE.toCharArray();
                } else {
                    password = KEY_PASSPHRASE.toCharArray();
                }
                return password;
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                final boolean shouldRetry = retryEnabled;
                if (retryEnabled) {
                    retryEnabled = false;
                }
                return shouldRetry;
            }
        };
        provider.init(getFile("pkcs8-rsa-2048-encrypted"), passwordFinder);
        assertEquals(KeyAlgorithm.RSA, provider.getPublic().getAlgorithm());
        assertEquals(KeyAlgorithm.RSA, provider.getPrivate().getAlgorithm());
    }

    @Test
    public void testPkcs8Ecdsa() throws IOException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        provider.init(getFile("pkcs8-ecdsa"));
        assertEquals(KeyAlgorithm.EC_KEYSTORE, provider.getPublic().getAlgorithm());
        assertEquals(KeyAlgorithm.EC_KEYSTORE, provider.getPrivate().getAlgorithm());
    }

    @Test
    public void testPkcs8Dsa() throws IOException {
        final PKCS8KeyFile provider = new PKCS8KeyFile();
        provider.init(getFile("pkcs8-dsa"));
        assertEquals(KeyAlgorithm.DSA, provider.getPublic().getAlgorithm());
        assertEquals(KeyAlgorithm.DSA, provider.getPrivate().getAlgorithm());
    }

    private File getFile(final String filename) {
        final String path = String.format("/keyformats/%s", filename);
        final URL resource = getClass().getResource(path);
        if (resource == null) {
            throw new IllegalArgumentException(String.format("Key File [%s] not found", path));
        }
        return new File(resource.getPath());
    }
}
