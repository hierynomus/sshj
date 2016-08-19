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

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.PKCS5KeyFile;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import net.schmizz.sshj.util.KeyUtil;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;

public class PKCS5KeyFileTest {

    static final FileKeyProvider rsa = new PKCS5KeyFile();

    static final String modulus = "a19f65e93926d9a2f5b52072db2c38c54e6cf0113d31fa92ff827b0f3bec609c45ea84264c88e64adba11ff093ed48ee0ed297757654b0884ab5a7e28b3c463bc9074b32837a2b69b61d914abf1d74ccd92b20fa44db3b31fb208c0dd44edaeb4ab097118e8ee374b6727b89ad6ce43f1b70c5a437ccebc36d2dad8ae973caad15cd89ae840fdae02cae42d241baef8fda8aa6bbaa54fd507a23338da6f06f61b34fb07d560e63fbce4a39c073e28573c2962cedb292b14b80d1b4e67b0465f2be0e38526232d0a7f88ce91a055fde082038a87ed91f3ef5ff971e30ea6cccf70d38498b186621c08f8fdceb8632992b480bf57fc218e91f2ca5936770fe9469";
    static final String pubExp = "23";
    static final String privExp = "57bcee2e2656eb2c94033d802dd62d726c6705fabad1fd0df86b67600a96431301620d395cbf5871c7af3d3974dfe5c30f5c60d95d7e6e75df69ed6c5a36a9c8aef554b5058b76a719b8478efa08ad1ebf08c8c25fe4b9bc0bfbb9be5d4f60e6213b4ab1c26ad33f5bba7d93e1cd65f65f5a79eb6ebfb32f930a2b0244378b4727acf83b5fb376c38d4abecc5dc3fc399e618e792d4c745d2dbbb9735242e5033129f2985ca3e28fa33cad2afe3e70e1b07ed2b6ec8a3f843fb4bffe3385ad211c6600618488f4ac70397e8eb036b82d811283dc728504cddbe1533c4dd31b1ec99ffa74fd0e3883a9cb3e2315cc1a56f55d38ed40520dd9ec91b4d2dd790d1b";

    static final String g = "23b0484f5ad9cba2b3dba7129419fbec7f8c014e22d3b19de4ebbca20d0ebd2e9f5225dabdd48de75f87e3193377fb1072c08433f82f6e6e581a319d4fc7d283cdcd2ae2000fe572c0a800fd47b7590d6a6afe3df54aedd57696c6538029daebf11d9e277edc0c7e905e237d3b9e6a6f674d83da5cc0131ac0be2e55ac69730e";
    static final String p = "92b746cf7c0e9ea35fd9b09b0c3dbdfde453468984698ff168fefef3f0457d29bcf81c88830ac1099223d00745423e44cdef66f4cdc3fad1d95ce2868b3e885c1d518c9fcda597d5c373f05f6f323553f60bd992404183dab41d82ab6d3b3ecf2dfc3c136fa67c4312ec0b7bbac77a634e1eb5dd9a62efd0ddab477d0b49c0b9";
    static final String q = "96a05e07b9e52d6f1137d11d5d270b568b94162f";
    static final String x = "8981aebb71c60b5951f0ab3ed1a00b5307742f43";
    static final String y = "7e845aada202d31004c52ab170cbe62ce9a962b9f4acbc67a57f62eb090a67b3faa53d38050f87b2b66ddf1185472f27842c3e3e58d025f9148a28f49ebdfb6efefee8ee10fe84a2d56535dddb301dfee15538108639e8a0ec7aa237ddb999f35b6a5c6b875052998233374163ad031f974d29c2631394436ae186b418348193";
    final char[] correctPassphrase = "test_passphrase".toCharArray();
    final char[] incorrectPassphrase = new char[]{' '};


    @Before
    public void setUp()
            throws UnsupportedEncodingException, GeneralSecurityException {
        rsa.init(new File("src/test/resources/id_rsa"));
    }

    @Test
    public void testKeys()
            throws IOException, GeneralSecurityException {
        assertEquals(KeyUtil.newRSAPublicKey(modulus, pubExp), rsa.getPublic());
        assertEquals(KeyUtil.newRSAPrivateKey(modulus, privExp), rsa.getPrivate());
    }

    @Test
    public void testType()
            throws IOException {
        assertEquals(rsa.getType(), KeyType.RSA);
    }

    final PasswordFinder givesOn3rdTry = new PasswordFinder() {
        int triesLeft = 3;

        @Override
        public char[] reqPassword(Resource resource) {
            if (triesLeft == 0)
                return correctPassphrase;
            else {
                triesLeft--;
                return incorrectPassphrase;
            }
        }

        @Override
        public boolean shouldRetry(Resource resource) {
            return triesLeft >= 0;
        }
    };

    @Test
    public void retries()
            throws IOException, GeneralSecurityException {
        FileKeyProvider dsa = new PKCS5KeyFile();
        dsa.init(new File("src/test/resources/id_dsa"), givesOn3rdTry);
        assertEquals(KeyUtil.newDSAPrivateKey(x, p, q, g), dsa.getPrivate());
    }
}
