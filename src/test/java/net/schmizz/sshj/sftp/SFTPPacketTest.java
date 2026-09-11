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

}
