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

import net.schmizz.sshj.sftp.Response.StatusCode;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class RemoteFile
        extends RemoteResource {

    public RemoteFile(Requester requester, String path, String handle) {
        super(requester, path, handle);
    }

    public RemoteFileInputStream getInputStream() {
        return new RemoteFileInputStream();
    }

    public RemoteFileOutputStream getOutputStream() {
        return new RemoteFileOutputStream();
    }

    public FileAttributes fetchAttributes()
            throws IOException {
        return requester.doRequest(newRequest(PacketType.FSTAT))
                        .ensurePacketTypeIs(PacketType.ATTRS)
                        .readFileAttributes();
    }

    public long length()
            throws IOException {
        return fetchAttributes().getSize();
    }

    public void setLength(long len)
            throws IOException {
        setAttributes(new FileAttributes.Builder().withSize(len).build());
    }

    public int read(long fileOffset, byte[] to, int offset, int len)
            throws IOException {
        Response res = requester.doRequest(newRequest(PacketType.READ).putUInt64(fileOffset).putUInt32(len));
        switch (res.getType()) {
            case DATA:
                int recvLen = res.readUInt32AsInt();
                System.arraycopy(res.array(), res.rpos(), to, offset, recvLen);
                return recvLen;

            case STATUS:
                res.ensureStatusIs(StatusCode.EOF);
                return -1;

            default:
                throw new SFTPException("Unexpected packet: " + res.getType());
        }
    }

    public void write(long fileOffset, byte[] data, int off, int len)
            throws IOException {
        requester.doRequest(newRequest(PacketType.WRITE)
                                    .putUInt64(fileOffset)
                                    .putUInt32(len - off)
                                    .putRawBytes(data, off, len)
        ).ensureStatusPacketIsOK();
    }

    public void setAttributes(FileAttributes attrs)
            throws IOException {
        requester.doRequest(newRequest(PacketType.FSETSTAT).putFileAttributes(attrs)).ensureStatusPacketIsOK();
    }

    public int getOutgoingPacketOverhead() {
        return 1 + // packet type
                4 + // request id
                4 + // next length
                handle.length() + // next
                8 + // file offset
                4 + // data length
                4; // packet length
    }

    public class RemoteFileOutputStream
            extends OutputStream {


        private final byte[] b = new byte[1];

        private long fileOffset;

        public RemoteFileOutputStream() {
            this(0);
        }

        public RemoteFileOutputStream(long fileOffset) {
            this.fileOffset = fileOffset;
        }

        @Override
        public void write(int w)
                throws IOException {
            b[0] = (byte) w;
            write(b, 0, 1);
        }

        @Override
        public void write(byte[] buf, int off, int len)
                throws IOException {
            RemoteFile.this.write(fileOffset, buf, off, len);
            fileOffset += len;
        }

    }

    public class RemoteFileInputStream
            extends InputStream {

        private final byte[] b = new byte[1];

        private long fileOffset;
        private long markPos;
        private long readLimit;

        public RemoteFileInputStream() {
            this(0);
        }

        public RemoteFileInputStream(int fileOffset) {
            this.fileOffset = fileOffset;
        }

        @Override
        public boolean markSupported() {
            return true;
        }

        @Override
        public void mark(int readLimit) {
            this.readLimit = readLimit;
            markPos = fileOffset;
        }

        @Override
        public void reset()
                throws IOException {
            fileOffset = markPos;
        }

        @Override
        public long skip(long n)
                throws IOException {
            return (this.fileOffset = Math.min(fileOffset + n, length()));
        }

        @Override
        public int read()
                throws IOException {
            return read(b, 0, 1) == -1 ? -1 : b[0] & 0xff;
        }

        @Override
        public int read(byte[] into, int off, int len)
                throws IOException {
            int read = RemoteFile.this.read(fileOffset, into, off, len);
            if (read != -1) {
                fileOffset += read;
                if (markPos != 0 && read > readLimit) // Invalidate mark position
                    markPos = 0;
            }
            return read;
        }

    }
}
