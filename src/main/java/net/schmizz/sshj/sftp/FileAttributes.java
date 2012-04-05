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
import net.schmizz.sshj.xfer.FilePermission;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public final class FileAttributes {

    public static final FileAttributes EMPTY = new FileAttributes();

    public static enum Flag {

        SIZE(0x00000001),
        UIDGID(0x00000002),
        MODE(0x00000004),
        ACMODTIME(0x00000008),
        EXTENDED(0x80000000);

        private final int flag;

        private Flag(int flag) {
            this.flag = flag;
        }

        public boolean isSet(int mask) {
            return (mask & flag) == flag;
        }

        public int get() {
            return flag;
        }

    }

    private final FileMode mode;
    private final int mask;
    private final long size;
    private final int uid;
    private final int gid;
    private final long atime;
    private final long mtime;
    private final Map<String, String> ext = new HashMap<String, String>();

    private FileAttributes() {
        size = atime = mtime = uid = gid = mask = 0;
        mode = new FileMode(0);
    }

    public FileAttributes(int mask, long size, int uid, int gid, FileMode mode, long atime, long mtime,
                          Map<String, String> ext) {
        this.mask = mask;
        this.size = size;
        this.uid = uid;
        this.gid = gid;
        this.mode = mode;
        this.atime = atime;
        this.mtime = mtime;
        this.ext.putAll(ext);
    }

    public boolean has(Flag flag) {
        return flag.isSet(mask);
    }

    public long getSize() {
        return size;
    }

    public int getUID() {
        return uid;
    }

    public int getGID() {
        return gid;
    }

    public FileMode getMode() {
        return mode;
    }

    public Set<FilePermission> getPermissions() {
        return mode.getPermissions();
    }

    public FileMode.Type getType() {
        return mode.getType();
    }

    public long getAtime() {
        return atime;
    }

    public long getMtime() {
        return mtime;
    }

    public String getExtended(String type) {
        return ext.get(type);
    }

    public byte[] toBytes() {
        Buffer.PlainBuffer buf = new Buffer.PlainBuffer();
        buf.putUInt32(mask);

        if (has(Flag.SIZE))
            buf.putUInt64(size);

        if (has(Flag.UIDGID)) {
            buf.putUInt32(uid);
            buf.putUInt32(gid);
        }

        if (has(Flag.MODE))
            buf.putUInt32(mode.getMask());

        if (has(Flag.ACMODTIME)) {
            buf.putUInt32(atime);
            buf.putUInt32(mtime);
        }

        if (has(Flag.EXTENDED)) {
            buf.putUInt32(ext.size());
            for (Entry<String, String> entry : ext.entrySet()) {
                buf.putString(entry.getKey());
                buf.putString(entry.getValue());
            }
        }
        return buf.getCompactData();
    }

    public static class Builder {

        private int mask;
        private long size;
        private long atime;
        private long mtime;
        private FileMode mode = new FileMode(0);
        private int uid;
        private int gid;
        private final Map<String, String> ext = new HashMap<String, String>();

        public Builder withSize(long size) {
            mask |= Flag.SIZE.get();
            this.size = size;
            return this;
        }

        public Builder withAtimeMtime(long atime, long mtime) {
            mask |= Flag.ACMODTIME.get();
            this.atime = atime;
            this.mtime = mtime;
            return this;
        }

        public Builder withUIDGID(int uid, int gid) {
            mask |= Flag.UIDGID.get();
            this.uid = uid;
            this.gid = gid;
            return this;
        }

        public Builder withPermissions(Set<FilePermission> perms) {
            mask |= Flag.MODE.get();
            this.mode = new FileMode((mode != null ? mode.getTypeMask() : 0) | FilePermission.toMask(perms));
            return this;
        }

        public Builder withPermissions(int perms) {
            mask |= Flag.MODE.get();
            this.mode = new FileMode((mode != null ? mode.getTypeMask() : 0) | perms);
            return this;
        }

        public Builder withType(FileMode.Type type) {
            mask |= Flag.MODE.get();
            this.mode = new FileMode(type.toMask() | (mode != null ? mode.getPermissionsMask() : 0));
            return this;
        }

        public Builder withExtended(String type, String data) {
            mask |= Flag.EXTENDED.get();
            ext.put(type, data);
            return this;
        }

        public Builder withExtended(Map<String, String> ext) {
            mask |= Flag.EXTENDED.get();
            this.ext.putAll(ext);
            return this;
        }

        public FileAttributes build() {
            return new FileAttributes(mask, size, uid, gid, mode, atime, mtime, ext);
        }

    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("[");

        if (has(Flag.SIZE))
            sb.append("size=").append(size).append(";");

        if (has(Flag.UIDGID))
            sb.append("uid=").append(size).append(",gid=").append(gid).append(";");

        if (has(Flag.MODE))
            sb.append("mode=").append(mode.toString()).append(";");

        if (has(Flag.ACMODTIME))
            sb.append("atime=").append(atime).append(",mtime=").append(mtime).append(";");

        if (has(Flag.EXTENDED))
            sb.append("ext=").append(ext);

        sb.append("]");

        return sb.toString();
    }

}
