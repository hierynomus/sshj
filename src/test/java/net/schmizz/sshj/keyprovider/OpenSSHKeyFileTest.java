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

import com.hierynomus.sshj.userauth.certificate.Certificate;
import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile;
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
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Scanner;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;

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

    @Test
    public void fromString()
            throws IOException, GeneralSecurityException {
        FileKeyProvider dsa = new OpenSSHKeyFile();
        String privateKey = readFile("src/test/resources/id_dsa");
        String publicKey = readFile("src/test/resources/id_dsa.pub");
        dsa.init(privateKey, publicKey,
                 PasswordUtils.createOneOff(correctPassphrase));
        assertEquals(dsa.getType(), KeyType.DSA);
        assertEquals(KeyUtil.newDSAPublicKey(y, p, q, g), dsa.getPublic());
        assertEquals(KeyUtil.newDSAPrivateKey(x, p, q, g), dsa.getPrivate());
    }

    @Test
    public void shouldHaveCorrectFingerprintForECDSA256() throws IOException, GeneralSecurityException {
        OpenSSHKeyFile keyFile = new OpenSSHKeyFile();
        keyFile.init(new File("src/test/resources/keytypes/test_ecdsa_nistp256"));
        String expected = "256 MD5:53:ae:db:ed:8f:2d:02:d4:d5:6c:24:bc:a4:66:88:79 root@itgcpkerberosstack-cbgateway-0-20151117031915 (ECDSA)\n";
        PublicKey aPublic = keyFile.getPublic();
        String sshjFingerprintSshjKey = net.schmizz.sshj.common.SecurityUtils.getFingerprint(aPublic);
        assertThat(expected, containsString(sshjFingerprintSshjKey));
    }

    @Test
    public void shouldHaveCorrectFingerprintForECDSA384() throws IOException, GeneralSecurityException {
        OpenSSHKeyFile keyFile = new OpenSSHKeyFile();
        keyFile.init(new File("src/test/resources/keytypes/test_ecdsa_nistp384"));
        String expected = "384 MD5:ee:9b:82:d1:47:01:16:1b:27:da:f5:27:fd:b2:eb:e2";
        PublicKey aPublic = keyFile.getPublic();
        String sshjFingerprintSshjKey = net.schmizz.sshj.common.SecurityUtils.getFingerprint(aPublic);
        assertThat(expected, containsString(sshjFingerprintSshjKey));
    }

    @Test
    public void shouldHaveCorrectFingerprintForECDSA521() throws IOException, GeneralSecurityException {
        OpenSSHKeyFile keyFile = new OpenSSHKeyFile();
        keyFile.init(new File("src/test/resources/keytypes/test_ecdsa_nistp521"));
        String expected = "521 MD5:22:e2:f4:3c:61:ae:e9:85:a1:4d:d9:6c:13:aa:eb:00";
        PublicKey aPublic = keyFile.getPublic();
        String sshjFingerprintSshjKey = net.schmizz.sshj.common.SecurityUtils.getFingerprint(aPublic);
        assertThat(expected, containsString(sshjFingerprintSshjKey));
    }

    @Test
    public void shouldHaveCorrectFingerprintForED25519() throws IOException {
        OpenSSHKeyV1KeyFile keyFile = new OpenSSHKeyV1KeyFile();
        keyFile.init(new File("src/test/resources/keytypes/test_ed25519"));
        String expected = "256 MD5:d3:5e:40:72:db:08:f1:6d:0c:d7:6d:35:0d:ba:7c:32 root@sshj (ED25519)\n";
        PublicKey aPublic = keyFile.getPublic();
        String sshjFingerprintSshjKey = net.schmizz.sshj.common.SecurityUtils.getFingerprint(aPublic);
        assertThat(expected, containsString(sshjFingerprintSshjKey));
    }

    @Test
    public void shouldLoadED25519PrivateKey() throws IOException {
        OpenSSHKeyV1KeyFile keyFile = new OpenSSHKeyV1KeyFile();
        keyFile.init(new File("src/test/resources/keytypes/test_ed25519"));
        PrivateKey aPrivate = keyFile.getPrivate();
        assertThat(aPrivate.getAlgorithm(), equalTo("EdDSA"));
    }

    @Test
    public void shouldSuccessfullyLoadSignedRSAPublicKey() throws IOException {
        FileKeyProvider keyFile = new OpenSSHKeyFile();
        keyFile.init(new File("src/test/resources/keytypes/certificate/test_rsa"),
                     PasswordUtils.createOneOff(correctPassphrase));
        assertNotNull(keyFile.getPrivate());
        PublicKey pubKey = keyFile.getPublic();
        assertEquals("RSA", pubKey.getAlgorithm());

        @SuppressWarnings("unchecked")
        Certificate<RSAPublicKey> certificate = (Certificate<RSAPublicKey>) pubKey;

        assertEquals(new BigInteger("9223372036854775809"), certificate.getSerial());
        assertEquals("testrsa", certificate.getId());

        assertEquals(2, certificate.getValidPrincipals().size());
        assertTrue(certificate.getValidPrincipals().contains("jeroen"));
        assertTrue(certificate.getValidPrincipals().contains("nobody"));

        assertEquals(parseDate("2017-04-11 17:38:00 -0400"), certificate.getValidAfter());
        assertEquals(parseDate("2017-04-11 18:09:27 -0400"), certificate.getValidBefore());

        assertEquals(0, certificate.getCritOptions().size());

        Map<String, String> extensions = certificate.getExtensions();
        assertEquals(5, extensions.size());
        assertEquals("", extensions.get("permit-X11-forwarding"));
        assertEquals("", extensions.get("permit-agent-forwarding"));
        assertEquals("", extensions.get("permit-port-forwarding"));
        assertEquals("", extensions.get("permit-pty"));
        assertEquals("", extensions.get("permit-user-rc"));

    }

    @Test
    public void shouldSuccessfullyLoadSignedDSAPublicKey() throws IOException {
        FileKeyProvider keyFile = new OpenSSHKeyFile();
        keyFile.init(new File("src/test/resources/keytypes/certificate/test_dsa"),
                     PasswordUtils.createOneOff(correctPassphrase));
        assertNotNull(keyFile.getPrivate());
        PublicKey pubKey = keyFile.getPublic();
        assertEquals("DSA", pubKey.getAlgorithm());

        @SuppressWarnings("unchecked")
        Certificate<RSAPublicKey> certificate = (Certificate<RSAPublicKey>) pubKey;

        assertEquals(new BigInteger("123"), certificate.getSerial());
        assertEquals("testdsa", certificate.getId());

        assertEquals(1, certificate.getValidPrincipals().size());
        assertTrue(certificate.getValidPrincipals().contains("jeroen"));

        assertEquals(parseDate("2017-04-11 17:37:00 -0400"), certificate.getValidAfter());
        assertEquals(parseDate("2017-04-12 03:38:49 -0400"), certificate.getValidBefore());

        assertEquals(1, certificate.getCritOptions().size());
        assertEquals("10.0.0.0/8", certificate.getCritOptions().get("source-address"));

        assertEquals(1, certificate.getExtensions().size());
        assertEquals("", certificate.getExtensions().get("permit-pty"));
    }

    @Before
    public void setup()
            throws UnsupportedEncodingException, GeneralSecurityException {
        if (!SecurityUtils.isBouncyCastleRegistered())
            throw new AssertionError("bouncy castle needed");
    }

    private String readFile(String pathname)
            throws IOException {
        StringBuilder fileContents = new StringBuilder();
        Scanner scanner = new Scanner(new File(pathname));
        String lineSeparator = System.getProperty("line.separator");
        try {
            while (scanner.hasNextLine()) {
                fileContents.append(scanner.nextLine() + lineSeparator);
            }
            return fileContents.toString();
        } finally {
            scanner.close();
        }
    }

    private Date parseDate(String date) {
        DateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");
        try {
            return f.parse(date);
        } catch (ParseException e) {
            return null;
        }
    }
}
