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
package net.schmizz.sshj.transport.mac;

import com.hierynomus.sshj.transport.mac.Macs;
import net.schmizz.sshj.common.SSHRuntimeException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseMacTest {
    private static final Charset CHARSET = Charset.forName("US-ASCII");
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(CHARSET);
    private static final String EXPECTED_HMAC = "24ddeed57ad91465c5b59dce74ef73778bfb0cb9";
    private static final String KEY = "et1Quo5ooCie6theel8i";

    @Test
    public void testResizeTooBigKeys() {
        BaseMAC hmac = Macs.HMACSHA1().create();
        hmac.init((KEY + "foo").getBytes(CHARSET));
        hmac.update(PLAIN_TEXT);
        assertThat(Hex.toHexString(hmac.doFinal()),  is(EXPECTED_HMAC));
    }

    @Test
    public void testUnknownAlgorithm() {
        assertThrows(SSHRuntimeException.class, () -> {
            BaseMAC hmac = new BaseMAC("AlgorithmThatDoesNotExist", 20, 20, false);
            hmac.init((KEY + "foo").getBytes(CHARSET));
            fail("Should not initialize a non-existent MAC");
        });
    }

    @Test
    public void testUpdateWithDoFinal() {
        BaseMAC hmac = initHmac();
        hmac.update(PLAIN_TEXT);
        assertThat(Hex.toHexString(hmac.doFinal()),  is(EXPECTED_HMAC));
    }

    @Test
    public void testUpdateWithRange() {
        BaseMAC hmac = initHmac();

        // a leading and trailing byte to the plaintext
        byte[] plainText = new byte[PLAIN_TEXT.length + 2];
        System.arraycopy(PLAIN_TEXT, 0, plainText, 1, PLAIN_TEXT.length);

        // update with the range from the second to penultimate byte
        hmac.update(plainText, 1, PLAIN_TEXT.length);
        assertThat(Hex.toHexString(hmac.doFinal()),  is(EXPECTED_HMAC));
    }

    @Test
    public void testDoFinalWithInput() {
        BaseMAC hmac = initHmac();
        assertThat(Hex.toHexString(hmac.doFinal(PLAIN_TEXT)), is(EXPECTED_HMAC));
    }

    @Test
    public void testUpdateWithDoFinalWithResultBuffer() {
        BaseMAC hmac = initHmac();
        byte[] resultBuf = new byte[20];
        hmac.update(PLAIN_TEXT);
        hmac.doFinal(resultBuf, 0);
        assertThat(Hex.toHexString(resultBuf), is(EXPECTED_HMAC));
    }

    private BaseMAC initHmac() {
        BaseMAC hmac = Macs.HMACSHA1().create();
        hmac.init(KEY.getBytes(CHARSET));
        return hmac;
    }
}
