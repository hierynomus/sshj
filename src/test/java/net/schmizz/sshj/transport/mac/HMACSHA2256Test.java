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

public class HMACSHA2256Test {
    private static final Charset CHARSET = StandardCharsets.US_ASCII;
    private static final byte[] PLAIN_TEXT = "Hello World".getBytes(CHARSET);
    private static final String EXPECTED_HMAC = "eb 22 07 b2 df 36 c7 48 5f 46 d1 be 30 41 8b c4 4e 81 34 b4 fd aa bb e1 6d 71 f5 6a b2 4f ce 88";

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
        byte[] resultBuf = new byte[32];
        hmac.update(PLAIN_TEXT);
        hmac.doFinal(resultBuf, 0);
        assertThat(BufferUtils.toHex(resultBuf), is(EXPECTED_HMAC));
    }

    private BaseMAC initHmac() {
        BaseMAC hmac = Macs.HMACSHA2256().create();
        hmac.init("koopiegh4reengah1que9Wiew7ohahPh".getBytes(CHARSET));
        return hmac;
    }
}
