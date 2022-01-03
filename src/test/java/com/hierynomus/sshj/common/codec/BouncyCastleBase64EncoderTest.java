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

import static com.hierynomus.sshj.common.codec.Base64ProviderTest.BYTES;
import static com.hierynomus.sshj.common.codec.Base64ProviderTest.BYTES_ENCODED;
import static org.junit.Assert.assertEquals;

public class BouncyCastleBase64EncoderTest {

    @Test
    public void testEncode() {
        final BouncyCastleBase64Encoder encoder = new BouncyCastleBase64Encoder();
        final String encoded = encoder.encode(BYTES);
        assertEquals(BYTES_ENCODED, encoded);
    }
}
