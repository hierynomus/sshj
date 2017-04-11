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
package net.schmizz.sshj.common;

import net.schmizz.sshj.common.Buffer.BufferException;
import net.schmizz.sshj.common.Buffer.PlainBuffer;

import static org.junit.Assert.*;

import org.junit.Test;

public class BufferTest {

    // Issue 72: previously, it entered an infinite loop trying to establish the buffer size
    @Test
    public void shouldThrowOnTooLargeCapacity() {
        PlainBuffer buffer = new PlainBuffer();
        try {
            buffer.ensureCapacity(Integer.MAX_VALUE);
            fail("Allegedly ensured buffer capacity of size " + Integer.MAX_VALUE);
        } catch (IllegalArgumentException e) {
            // success
        }
    }

    // Issue 72: previously, it entered an infinite loop trying to establish the buffer size
    @Test
    public void shouldThrowOnTooLargeInitialCapacity() {
        try {
            new PlainBuffer(Integer.MAX_VALUE);
            fail("Allegedly created buffer with size " + Integer.MAX_VALUE);
        } catch (IllegalArgumentException e) {
            // success
        }
    }

    @Test
    public void shouldCorrectlyEncodeAndDecodeUInt64Types() throws BufferException {
        // This number fits into a unsigned 64 bit integer but not a signed one.
        long bigUint64 = Long.MAX_VALUE + 2;
        assertEquals(0x8000000000000001l, bigUint64);
        assertTrue(bigUint64 < 0);

        Buffer<PlainBuffer> buff = new PlainBuffer();
        buff.putUInt64(bigUint64);
        byte[] data = buff.getCompactData();
        assertEquals(8, data.length);
        assertEquals((byte) 0x80, data[0]);
        assertEquals((byte) 0x00, data[1]);
        assertEquals((byte) 0x00, data[2]);
        assertEquals((byte) 0x00, data[3]);
        assertEquals((byte) 0x00, data[4]);
        assertEquals((byte) 0x00, data[5]);
        assertEquals((byte) 0x00, data[6]);
        assertEquals((byte) 0x01, data[7]);

        byte[] asBinary = new byte[] { (byte) 0x80,
                                       (byte) 0x00,
                                       (byte) 0x00,
                                       (byte) 0x00,
                                       (byte) 0x00,
                                       (byte) 0x00,
                                       (byte) 0x00,
                                       (byte) 0x01 };
        buff = new PlainBuffer(asBinary);
        assertEquals(bigUint64, buff.readUInt64());
    }
}
