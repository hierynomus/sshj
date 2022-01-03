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
package com.hierynomus.sshj.common.codec;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class Base64ProviderTest {

    static final byte[] BYTES = new byte[]{0, 1, 2, 3};

    static final String BYTES_ENCODED = "AAECAw==";

    @Test
    public void testGetEncoderEncode() {
        final Base64Encoder encoder = Base64Provider.getEncoder();
        final String encoded = encoder.encode(BYTES);
        assertEquals(BYTES_ENCODED, encoded);
    }

    @Test
    public void testGetDecoderDecode() {
        final Base64Decoder decoder = Base64Provider.getDecoder();
        final byte[] decoded = decoder.decode(BYTES_ENCODED);
        assertArrayEquals(BYTES, decoded);
    }
}
