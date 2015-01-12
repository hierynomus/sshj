/**
 * Copyright 2009 sshj contributors
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

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.Charset;

import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.is;

public class HMACSHA2512Test {
    private static final Charset CHARSET = Charset.forName("US-ASCII");
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(CHARSET);
    private static final String EXPECTED_HMAC = "28929cffc903039ef18cbc9cea6fd5f1420763af297a470d731236ed1f5a4c61d64dfccf6529265205bec932f2f7850c8ae4de1dc1a5259dc5b1fd85d8e62c04";

    @Test
    public void testUpdateWithDoFinal() {
        HMACSHA2512 hmac = initHmac();
        hmac.update(PLAIN_TEXT);
        assertThat(Hex.toHexString(hmac.doFinal()), is(EXPECTED_HMAC));
    }

    @Test
    public void testDoFinalWithInput() {
        HMACSHA2512 hmac = initHmac();
        assertThat(Hex.toHexString(hmac.doFinal(PLAIN_TEXT)), is(EXPECTED_HMAC));
    }

    @Test
    public void testUpdateWithDoFinalWithResultBuffer() {
        HMACSHA2512 hmac = initHmac();
        byte[] resultBuf = new byte[64];
        hmac.update(PLAIN_TEXT);
        hmac.doFinal(resultBuf, 0);
        assertThat(Hex.toHexString(resultBuf), is(EXPECTED_HMAC));
    }

    private HMACSHA2512 initHmac() {
        HMACSHA2512 hmac = new HMACSHA2512();
        hmac.init("paishiengu1jaeTie5OoTu2eib7Kohqueicie7ahLohfoothahpeivi5weik1EiB".getBytes(CHARSET));
        return hmac;
    }
}