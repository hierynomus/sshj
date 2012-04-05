/*
 * Copyright 2010-2012 sshj contributors
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

import net.schmizz.sshj.common.Buffer;

public class SFTPPacket<T extends SFTPPacket<T>>
        extends Buffer<T> {

    public SFTPPacket() {
        super();
    }

    public SFTPPacket(Buffer<T> buf) {
        super(buf);
    }

    public SFTPPacket(PacketType pt) {
        super();
        putByte(pt.toByte());
    }

    public FileAttributes readFileAttributes()
            throws SFTPException {
        final FileAttributes.Builder builder = new FileAttributes.Builder();
        try {
            final int mask = readUInt32AsInt();
            if (FileAttributes.Flag.SIZE.isSet(mask))
                builder.withSize(readUInt64());
            if (FileAttributes.Flag.UIDGID.isSet(mask))
                builder.withUIDGID(readUInt32AsInt(), readUInt32AsInt());
            if (FileAttributes.Flag.MODE.isSet(mask))
                builder.withPermissions(readUInt32AsInt());
            if (FileAttributes.Flag.ACMODTIME.isSet(mask))
                builder.withAtimeMtime(readUInt32AsInt(), readUInt32AsInt());
            if (FileAttributes.Flag.EXTENDED.isSet(mask)) {
                final int extCount = readUInt32AsInt();
                for (int i = 0; i < extCount; i++)
                    builder.withExtended(readString(), readString());
            }
        } catch (BufferException be) {
            throw new SFTPException(be);
        }
        return builder.build();
    }

    public PacketType readType()
            throws SFTPException {
        try {
            return PacketType.fromByte(readByte());
        } catch (BufferException be) {
            throw new SFTPException(be);
        }
    }

    public T putFileAttributes(FileAttributes fa) {
        return putRawBytes(fa.toBytes());
    }

    public T putType(PacketType type) {
        return putByte(type.toByte());
    }

}
