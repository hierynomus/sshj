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
/*
* Copyright 2010, 2011 sshj contributors
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
package net.schmizz.sshj.util;

import net.schmizz.sshj.common.Buffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.*;

/** Tests {@link Buffer} functionality */
public class BufferTest {

    private Buffer.PlainBuffer posBuf;
    private Buffer.PlainBuffer handyBuf;

    @BeforeEach
    public void setUp()
            throws UnsupportedEncodingException, GeneralSecurityException {
        // for position test
        byte[] data = "Hello".getBytes(StandardCharsets.UTF_8);
        posBuf = new Buffer.PlainBuffer(data);
        handyBuf = new Buffer.PlainBuffer();
    }

    @Test
    public void testDataTypes()
            throws Buffer.BufferException {
        // bool
        assertEquals(handyBuf.putBoolean(true).readBoolean(), true);

        // byte
        assertEquals(handyBuf.putByte((byte) 10).readByte(), (byte) 10);

        // byte array
        assertArrayEquals(handyBuf.putBytes("some string".getBytes()).readBytes(), "some string".getBytes());

        // mpint
        BigInteger bi = new BigInteger("1111111111111111111111111111111");
        assertEquals(handyBuf.putMPInt(bi).readMPInt(), bi);

        // string
        assertEquals(handyBuf.putString("some string").readString(), "some string");

        // uint32
        assertEquals(handyBuf.putUInt32(0xffffffffL).readUInt32(), 0xffffffffL);
    }

    @Test
    public void testPassword()
            throws Buffer.BufferException {
        char[] pass = "lolcatz".toCharArray();
        // test if put correctly as a string
        assertEquals(new Buffer.PlainBuffer().putSensitiveString(pass).readString(), "lolcatz");
        // test that char[] was blanked out
        assertArrayEquals(pass, "       ".toCharArray());
    }

    @Test
    public void testPosition()
            throws UnsupportedEncodingException, Buffer.BufferException {
        assertEquals(5, posBuf.wpos());
        assertEquals(0, posBuf.rpos());
        assertEquals(5, posBuf.available());
        // read some bytes
        byte b = posBuf.readByte();
        assertEquals(b, (byte) 'H');
        assertEquals(1, posBuf.rpos());
        assertEquals(4, posBuf.available());
    }

    @Test
    public void testPublickey() {
        // TODO stub
    }

    @Test
    public void testSignature() {
        // TODO stub
    }

    @Test
    public void testUnderflow() throws Buffer.BufferException {
        assertThrows(Buffer.BufferException.class, () -> {
            // exhaust the buffer
            for (int i = 0; i < 5; ++i)
                posBuf.readByte();
            // underflow
            posBuf.readByte();
        });
    }

}
