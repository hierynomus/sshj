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
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class HMACMD5Test {
    private static final Charset CHARSET = StandardCharsets.US_ASCII;
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(CHARSET);
    private static final String EXPECTED_HMAC = "df f3 3c 50 74 63 f9 cf 08 8a 5c e8 d9 69 c3 86";

    @Test
    public void testUpdateWithDoFinal() {
        BaseMAC hmac = initHmac();
        hmac.update(PLAIN_TEXT);
        assertThat(BufferUtils.toHex(hmac.doFinal()), is(EXPECTED_HMAC));
    }

    @Test
    public void testDoFinalWithInput() {
        BaseMAC hmac = initHmac();
        assertThat(BufferUtils.toHex(hmac.doFinal(PLAIN_TEXT)), is(EXPECTED_HMAC));
    }

    @Test
    public void testUpdateWithDoFinalWithResultBuffer() {
        BaseMAC hmac = initHmac();
        byte[] resultBuf = new byte[16];
        hmac.update(PLAIN_TEXT);
        hmac.doFinal(resultBuf, 0);
        assertThat(BufferUtils.toHex(resultBuf), is(EXPECTED_HMAC));
    }

    private BaseMAC initHmac() {
        BaseMAC hmac = Macs.HMACMD5().create();
        hmac.init("ohBahfei6pee5dai".getBytes(CHARSET));
        return hmac;
    }
}
