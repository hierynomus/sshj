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
package net.schmizz.sshj.sftp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SFTPPacketTest {

    // Issue 1025: some SFTP server implementations (e.g. Apache MINA sshd >= 2.1.16) report a size of
    // 0xFFFFFFFFFFFFFFFF for directories, which previously caused readFileAttributes() to throw.
    @Test
    public void shouldReadFileAttributesWithAllOnesSize() throws SFTPException {
        SFTPPacket<Request> packet = new SFTPPacket<Request>();
        packet.putUInt32(FileAttributes.Flag.SIZE.get());
        packet.putRawBytes(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                         (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });

        FileAttributes attrs = packet.readFileAttributes();

        assertEquals(-1L, attrs.getSize());
    }

    @Test
    public void shouldReadFileAttributesWithNormalSize() throws SFTPException {
        SFTPPacket<Request> packet = new SFTPPacket<Request>();
        packet.putUInt32(FileAttributes.Flag.SIZE.get());
        packet.putUInt64(1234L);

        FileAttributes attrs = packet.readFileAttributes();

        assertEquals(1234L, attrs.getSize());
    }

    // Issue 980: SFTP v3 atime and mtime are unsigned 32-bit integers (uint32), supporting timestamps
    // past 2038-01-19 (Integer.MAX_VALUE) up to 2106-02-07 (0xFFFFFFFF).
    @Test
    public void shouldReadFileAttributesWithPost2038AtimeAndMtime() throws SFTPException {
        long atime = 0x80000000L; // 2038-01-19T03:14:08Z (Integer.MAX_VALUE + 1)
        long mtime = 2522880000L; // 2049-12-12T00:00:00Z

        SFTPPacket<Request> packet = new SFTPPacket<Request>();
        packet.putUInt32(FileAttributes.Flag.ACMODTIME.get());
        packet.putUInt32(atime);
        packet.putUInt32(mtime);

        FileAttributes attrs = packet.readFileAttributes();

        assertEquals(atime, attrs.getAtime());
        assertEquals(mtime, attrs.getMtime());
    }

    @Test
    public void shouldReadFileAttributesWithMaxUnsigned32BitAtimeAndMtime() throws SFTPException {
        long maxUInt32 = 0xFFFFFFFFL; // 2106-02-07T06:28:15Z

        SFTPPacket<Request> packet = new SFTPPacket<Request>();
        packet.putUInt32(FileAttributes.Flag.ACMODTIME.get());
        packet.putUInt32(maxUInt32);
        packet.putUInt32(maxUInt32);

        FileAttributes attrs = packet.readFileAttributes();

        assertEquals(maxUInt32, attrs.getAtime());
        assertEquals(maxUInt32, attrs.getMtime());
    }

    @Test
    public void shouldRoundTripPost2038FileAttributes() throws SFTPException {
        long atime = 2522880000L; // 2049-12-12T00:00:00Z
        long mtime = 0xFFFFFFFFL; // 2106-02-07T06:28:15Z
        FileAttributes original = new FileAttributes.Builder()
                .withAtimeMtime(atime, mtime)
                .build();

        SFTPPacket<Request> packet = new SFTPPacket<Request>();
        packet.putFileAttributes(original);
        FileAttributes readBack = packet.readFileAttributes();

        assertEquals(atime, readBack.getAtime());
        assertEquals(mtime, readBack.getMtime());
        assertArrayEquals(original.toBytes(), readBack.toBytes());
    }

}
