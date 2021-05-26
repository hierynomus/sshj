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
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class BufferTest {

    @Test
    public void testNegativeInteger() throws BufferException {
        byte[] negativeInt = new byte[] { (byte) 0xB8,
                                          (byte) 0x4B,
                                          (byte) 0xF4,
                                          (byte) 0x38 };
        PlainBuffer buffer = new PlainBuffer(negativeInt);
        assertEquals(buffer.readUInt32AsInt(),-1202981832);

        PlainBuffer buff = new PlainBuffer();
        buff.ensureCapacity(4);
        buff.putUInt32FromInt(-1202981832);
        byte[] data = buff.getCompactData();
        assertEquals(data[0], (byte) 0xB8);
        assertEquals(data[1], (byte) 0x4B);
        assertEquals(data[2], (byte) 0xF4);
        assertEquals(data[3], (byte) 0x38);
    }

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
    public void shouldThrowOnPutNegativeLongUInt64() {
        try {
            new PlainBuffer().putUInt64(-1l);
            fail("Added negative uint64 to buffer?");
        } catch (IllegalArgumentException e) {
            // success
        }
    }

    @Test
    public void shouldThrowOnReadNegativeLongUInt64() {
        byte[] negativeLong = new byte[] { (byte) 0x80,
                                           (byte) 0x00,
                                           (byte) 0x00,
                                           (byte) 0x00,
                                           (byte) 0x00,
                                           (byte) 0x00,
                                           (byte) 0x00,
                                           (byte) 0x01 };
        Buffer<?> buff = new PlainBuffer(negativeLong);

        try {
            buff.readUInt64();
            fail("Read negative uint64 from buffer?");
        } catch (BufferException e) {
            // success
        }
    }

    @Test
    public void shouldThrowOnPutNegativeBigIntegerUInt64() {
        try {
            new PlainBuffer().putUInt64(new BigInteger("-1"));
            fail("Added negative uint64 to buffer?");
        } catch (IllegalArgumentException e) {
            // success
        }
    }

    @Test
    public void shouldHaveCorrectValueForMaxUInt64() {
        byte[] maxUInt64InBytes = new byte[] { (byte) 0xFF, (byte) 0xFF,
                                               (byte) 0xFF, (byte) 0xFF,
                                               (byte) 0xFF, (byte) 0xFF,
                                               (byte) 0xFF, (byte) 0xFF };
        BigInteger maxUInt64 = new BigInteger(1, maxUInt64InBytes);
        new PlainBuffer().putUInt64(maxUInt64); // no exception

        BigInteger tooBig = maxUInt64.add(BigInteger.ONE);
        try {
            new PlainBuffer().putUInt64(tooBig);
            fail("Added 2^64 (too big) as uint64 to buffer?");
        } catch (IllegalArgumentException e) {
            // success
        }
    }

    @Test
    public void shouldCorrectlyEncodeAndDecodeUInt64Types() throws BufferException {
        // This number fits into a unsigned 64 bit integer but not a signed one.
        BigInteger bigUint64 = BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE).add(BigInteger.ONE);
        assertEquals(0x8000000000000001l, bigUint64.longValue());

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
        assertEquals(bigUint64, buff.readUInt64AsBigInteger());
    }

    @Test
    public void shouldHaveSameUInt64EncodingForBigIntegerAndLong() {
        long[] values = { 0l, 1l, 232634978082517765l, Long.MAX_VALUE - 1, Long.MAX_VALUE };
        for (long value : values) {
            byte[] bytesBigInt = new PlainBuffer().putUInt64(BigInteger.valueOf(value)).getCompactData();
            byte[] bytesLong = new PlainBuffer().putUInt64(value).getCompactData();
            assertArrayEquals("Value: " + value, bytesLong, bytesBigInt);
        }
    }


    @Test
    public void shouldExpandCapacityOfUInt32(){
        PlainBuffer buf = new PlainBuffer();
        for(int i=0;i<Buffer.DEFAULT_SIZE+1;i+=4) {
            buf.putUInt32(1l);
        }
        /* Buffer should have been expanded at this point*/
        assertEquals(Buffer.DEFAULT_SIZE*2,buf.data.length);
    }

    @Test
    public void shouldExpandCapacityOfUInt64(){
        BigInteger bigUint64 = BigInteger.valueOf(Long.MAX_VALUE);
        PlainBuffer buf = new PlainBuffer();
        assertEquals(Buffer.DEFAULT_SIZE,buf.data.length);
        for(int i=0;i<Buffer.DEFAULT_SIZE+1;i+=8) {
            buf.putUInt64(bigUint64.longValue());
        }
        /* Buffer should have been expanded at this point*/
        assertEquals(Buffer.DEFAULT_SIZE*2,buf.data.length);
    }

}
