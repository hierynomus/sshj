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

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.Charset;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class HMACMD596Test {
    private static final Charset CHARSET = Charset.forName("US-ASCII");
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(CHARSET);
    private static final String EXPECTED_HMAC = "dff33c507463f9cf088a5ce8";

    @Test
    public void testUpdateWithDoFinal() {
        HMACMD596 hmac = initHmac();
        hmac.update(PLAIN_TEXT);
        assertThat(Hex.toHexString(hmac.doFinal()), is(EXPECTED_HMAC));
    }

    @Test
    public void testDoFinalWithInput() {
        HMACMD596 hmac = initHmac();
        assertThat(Hex.toHexString(hmac.doFinal(PLAIN_TEXT)),
                is(EXPECTED_HMAC));
    }

    @Test
    public void testUpdateWithDoFinalWithResultBuffer() {
        HMACMD596 hmac = initHmac();
        byte[] resultBuf = new byte[12];
        hmac.update(PLAIN_TEXT);
        hmac.doFinal(resultBuf, 0);
        assertThat(Hex.toHexString(resultBuf), is(EXPECTED_HMAC));
    }

    private HMACMD596 initHmac() {
        HMACMD596 hmac = new HMACMD596();
        hmac.init("ohBahfei6pee5dai".getBytes(CHARSET));
        return hmac;
    }
}
