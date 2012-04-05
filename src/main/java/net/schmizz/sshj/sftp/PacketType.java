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

public enum PacketType {

    UNKNOWN(0),
    INIT(1),
    VERSION(2),
    OPEN(3),
    CLOSE(4),
    READ(5),
    WRITE(6),
    LSTAT(7),
    FSTAT(8),
    SETSTAT(9),
    FSETSTAT(10),
    OPENDIR(11),
    READDIR(12),
    REMOVE(13),
    MKDIR(14),
    RMDIR(15),
    REALPATH(16),
    STAT(17),
    RENAME(18),
    READLINK(19),
    SYMLINK(20),
    STATUS(101),
    HANDLE(102),
    DATA(103),
    NAME(104),
    ATTRS(105),
    EXTENDED(200),
    EXTENDED_REPLY(201);

    private final byte b;

    private static final PacketType[] cache = new PacketType[256];

    static {
        for (PacketType t : PacketType.values())
            cache[t.toByte() & 0xff] = t;
    }

    private PacketType(int b) {
        this.b = (byte) b;
    }

    public static PacketType fromByte(byte b) {
        return cache[b & 0xff];
    }

    public byte toByte() {
        return b;
    }

}
