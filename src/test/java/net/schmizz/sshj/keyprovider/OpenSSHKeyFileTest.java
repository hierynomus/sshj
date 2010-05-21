/*
 * Copyright 2010 Shikhar Bhushan
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
import net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUtils;
import net.schmizz.sshj.userauth.password.Resource;
import net.schmizz.sshj.util.KeyUtil;
import org.apache.sshd.common.util.SecurityUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class OpenSSHKeyFileTest {

    static final String g = "23b0484f5ad9cba2b3dba7129419fbec7f8c014e22d3b19de4ebbca20d0ebd2e9f5225dabdd48de75f87e3193377fb1072c08433f82f6e6e581a319d4fc7d283cdcd2ae2000fe572c0a800fd47b7590d6a6afe3df54aedd57696c6538029daebf11d9e277edc0c7e905e237d3b9e6a6f674d83da5cc0131ac0be2e55ac69730e";
    static final String p = "92b746cf7c0e9ea35fd9b09b0c3dbdfde453468984698ff168fefef3f0457d29bcf81c88830ac1099223d00745423e44cdef66f4cdc3fad1d95ce2868b3e885c1d518c9fcda597d5c373f05f6f323553f60bd992404183dab41d82ab6d3b3ecf2dfc3c136fa67c4312ec0b7bbac77a634e1eb5dd9a62efd0ddab477d0b49c0b9";
    static final String q = "96a05e07b9e52d6f1137d11d5d270b568b94162f";
    static final String x = "8981aebb71c60b5951f0ab3ed1a00b5307742f43";
    static final String y = "7e845aada202d31004c52ab170cbe62ce9a962b9f4acbc67a57f62eb090a67b3faa53d38050f87b2b66ddf1185472f27842c3e3e58d025f9148a28f49ebdfb6efefee8ee10fe84a2d56535dddb301dfee15538108639e8a0ec7aa237ddb999f35b6a5c6b875052998233374163ad031f974d29c2631394436ae186b418348193";

    boolean readyToProvide;

    final char[] correctPassphrase = "test_passphrase".toCharArray();
    final char[] incorrectPassphrase = new char[]{' '};

    final PasswordFinder onlyGivesWhenReady = new PasswordFinder() {
        @Override
        public char[] reqPassword(Resource resource) {
            if (!readyToProvide)
                throw new AssertionError("Password requested too soon");

            return correctPassphrase;
        }

        @Override
        public boolean shouldRetry(Resource resource) {
            return false;
        }
    };

    int triesLeft = 3;

    final PasswordFinder givesOn3rdTry = new PasswordFinder() {
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
    public void blankingOut()
            throws IOException, GeneralSecurityException {
        FileKeyProvider dsa = new OpenSSHKeyFile();
        dsa.init(new File("src/test/resources/id_dsa"), PasswordUtils.createOneOff(correctPassphrase));
        assertEquals(KeyUtil.newDSAPrivateKey(x, p, q, g), dsa.getPrivate());

        char[] blank = new char[correctPassphrase.length];
        Arrays.fill(blank, ' ');
        assertArrayEquals(blank, correctPassphrase);
    }

    @Test
    public void getters()
            throws IOException, GeneralSecurityException {
        FileKeyProvider dsa = new OpenSSHKeyFile();
        dsa.init(new File("src/test/resources/id_dsa"), onlyGivesWhenReady);
        assertEquals(dsa.getType(), KeyType.DSA);
        assertEquals(KeyUtil.newDSAPublicKey(y, p, q, g), dsa.getPublic());
        readyToProvide = true;
        assertEquals(KeyUtil.newDSAPrivateKey(x, p, q, g), dsa.getPrivate());
    }

    @Test
    public void retries()
            throws IOException, GeneralSecurityException {
        FileKeyProvider dsa = new OpenSSHKeyFile();
        dsa.init(new File("src/test/resources/id_dsa"), givesOn3rdTry);
        assertEquals(KeyUtil.newDSAPrivateKey(x, p, q, g), dsa.getPrivate());
    }

    @Before
    public void setup()
            throws UnsupportedEncodingException, GeneralSecurityException {
        if (!SecurityUtils.isBouncyCastleRegistered())
            throw new AssertionError("bouncy castle needed");
    }

}