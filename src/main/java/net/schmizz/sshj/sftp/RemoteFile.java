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

import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.sftp.Response.StatusCode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.TimeUnit;

public class RemoteFile
        extends RemoteResource {

    public RemoteFile(SFTPEngine requester, String path, byte[] handle) {
        super(requester, path, handle);
    }

    public FileAttributes fetchAttributes() throws IOException {
        return requester.request(newRequest(PacketType.FSTAT))
                .retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .ensurePacketTypeIs(PacketType.ATTRS)
                .readFileAttributes();
    }

    public long length() throws IOException {
        return fetchAttributes().getSize();
    }

    public void setLength(long len) throws IOException {
        setAttributes(new FileAttributes.Builder().withSize(len).build());
    }

    public int read(long fileOffset, byte[] to, int offset, int len) throws IOException {
        final Response res = asyncRead(fileOffset, len).retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS);
        return checkReadResponse(res, to, offset);
    }

    protected Promise<Response, SFTPException> asyncRead(long fileOffset, int len) throws IOException {
        return requester.request(newRequest(PacketType.READ).putUInt64(fileOffset).putUInt32(len));
    }

    protected int checkReadResponse(Response res, byte[] to, int offset) throws Buffer.BufferException, SFTPException {
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

    public void write(long fileOffset, byte[] data, int off, int len) throws IOException {
        checkWriteResponse(asyncWrite(fileOffset, data, off, len));
    }

    protected Promise<Response, SFTPException> asyncWrite(long fileOffset, byte[] data, int off, int len)
            throws IOException {
        return requester.request(newRequest(PacketType.WRITE)
                .putUInt64(fileOffset)
                .putString(data, off, len)
        );
    }

    private void checkWriteResponse(Promise<Response, SFTPException> responsePromise) throws SFTPException {
        responsePromise.retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS).ensureStatusPacketIsOK();
    }

    public void setAttributes(FileAttributes attrs) throws IOException {
        requester.request(newRequest(PacketType.FSETSTAT).putFileAttributes(attrs))
                .retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS).ensureStatusPacketIsOK();
    }

    public int getOutgoingPacketOverhead() {
        return 1 + // packet type
                4 + // request id
                4 + // next length
                handle.length + // next
                8 + // file offset
                4 + // data length
                4; // packet length
    }

    public class RemoteFileOutputStream
            extends OutputStream {

        private final byte[] b = new byte[1];

        private final int maxUnconfirmedWrites;
        private final Queue<Promise<Response, SFTPException>> unconfirmedWrites;

        private long fileOffset;

        public RemoteFileOutputStream() {
            this(0);
        }

        public RemoteFileOutputStream(long startingOffset) {
            this(startingOffset, 0);
        }

        public RemoteFileOutputStream(long startingOffset, int maxUnconfirmedWrites) {
            this.fileOffset = startingOffset;
            this.maxUnconfirmedWrites = maxUnconfirmedWrites;
            this.unconfirmedWrites = new LinkedList<Promise<Response, SFTPException>>();
        }

        @Override
        public void write(int w) throws IOException {
            b[0] = (byte) w;
            write(b, 0, 1);
        }

        @Override
        public void write(byte[] buf, int off, int len) throws IOException {
            if (unconfirmedWrites.size() > maxUnconfirmedWrites) {
                checkWriteResponse(unconfirmedWrites.remove());
            }
            unconfirmedWrites.add(RemoteFile.this.asyncWrite(fileOffset, buf, off, len));
            fileOffset += len;
        }

        @Override
        public void flush() throws IOException {
            while (!unconfirmedWrites.isEmpty()) {
                checkWriteResponse(unconfirmedWrites.remove());
            }
        }

        @Override
        public void close() throws IOException {
            flush();
        }

    }

    public class RemoteFileInputStream extends InputStream {

        private final byte[] b = new byte[1];

        private long fileOffset;
        private long markPos;
        private long readLimit;

        public RemoteFileInputStream() {
            this(0);
        }

        public RemoteFileInputStream(long fileOffset) {
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
        public void reset() throws IOException {
            fileOffset = markPos;
        }

        @Override
        public long skip(long n) throws IOException {
            final long fileLength = length();
            final Long previousFileOffset = fileOffset;
            fileOffset = Math.min(fileOffset + n, fileLength);
            return fileOffset - previousFileOffset;
        }

        @Override
        public int read() throws IOException {
            return read(b, 0, 1) == -1 ? -1 : b[0] & 0xff;
        }

        @Override
        public int read(byte[] into, int off, int len) throws IOException {
            int read = RemoteFile.this.read(fileOffset, into, off, len);
            if (read != -1) {
                fileOffset += read;
                if (markPos != 0 && read > readLimit) {
                    // Invalidate mark position
                    markPos = 0;
                }
            }
            return read;
        }

    }

    public class ReadAheadRemoteFileInputStream
            extends InputStream {
        private class UnconfirmedRead {
            private final long offset;
            private final Promise<Response, SFTPException> promise;
            private final int length;

            private UnconfirmedRead(long offset, int length, Promise<Response, SFTPException> promise) {
                this.offset = offset;
                this.length = length;
                this.promise = promise;
            }

            UnconfirmedRead(long offset, int length) throws IOException {
                this(offset, length, RemoteFile.this.asyncRead(offset, length));
            }

            public long getOffset() {
                return offset;
            }

            public Promise<Response, SFTPException> getPromise() {
                return promise;
            }

            public int getLength() {
                return length;
            }
        }

        private final byte[] b = new byte[1];

        private final int maxUnconfirmedReads;
        private final long readAheadLimit;
        private final Deque<UnconfirmedRead> unconfirmedReads = new ArrayDeque<>();

        private long currentOffset;
        private int maxReadLength = Integer.MAX_VALUE;
        private boolean eof;

        public ReadAheadRemoteFileInputStream(int maxUnconfirmedReads) {
            this(maxUnconfirmedReads, 0L, -1L);
        }

        /**
         *
         * @param maxUnconfirmedReads Maximum number of unconfirmed requests to send
         * @param fileOffset Initial offset in file to read from
         * @param readAheadLimit Read ahead is disabled after this limit has been reached
         */
        public ReadAheadRemoteFileInputStream(int maxUnconfirmedReads, long fileOffset, long readAheadLimit) {
            assert 0 <= maxUnconfirmedReads;
            assert 0 <= fileOffset;

            this.maxUnconfirmedReads = maxUnconfirmedReads;
            this.currentOffset = fileOffset;
            this.readAheadLimit = readAheadLimit > 0 ? fileOffset + readAheadLimit : Long.MAX_VALUE;
        }

        private ByteArrayInputStream pending = new ByteArrayInputStream(new byte[0]);

        private boolean retrieveUnconfirmedRead(boolean blocking) throws IOException {
            final UnconfirmedRead unconfirmedRead = unconfirmedReads.peek();
            if (unconfirmedRead == null || !blocking && !unconfirmedRead.getPromise().isDelivered()) {
                return false;
            }
            unconfirmedReads.remove(unconfirmedRead);

            final Response res = unconfirmedRead.promise.retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS);
            switch (res.getType()) {
                case DATA:
                    int recvLen = res.readUInt32AsInt();
                    if (unconfirmedRead.offset == currentOffset) {
                        currentOffset += recvLen;
                        pending = new ByteArrayInputStream(res.array(), res.rpos(), recvLen);

                        if (recvLen < unconfirmedRead.length) {
                            // The server returned a packet smaller than the client had requested.
                            // It can be caused by at least one of the following:
                            // * The file has been read fully. Then, few futile read requests can be sent during
                            //   the next read(), but the file will be downloaded correctly anyway.
                            // * The server shapes the request length. Then, the read window will be adjusted,
                            //   and all further read-ahead requests won't be shaped.
                            // * The file on the server is not a regular file, it is something like fifo.
                            //   Then, the window will shrink, and the client will start reading the file slower than it
                            //   hypothetically can. It must be a rare case, and it is not worth implementing a sort of
                            //   congestion control algorithm here.
                            maxReadLength = recvLen;
                            unconfirmedReads.clear();
                        }
                    }
                    break;

                case STATUS:
                    res.ensureStatusIs(Response.StatusCode.EOF);
                    eof = true;
                    break;

                default:
                    throw new SFTPException("Unexpected packet: " + res.getType());
            }
            return true;
        }

        @Override
        public int read()
                throws IOException {
            return read(b, 0, 1) == -1 ? -1 : b[0] & 0xff;
        }

        @Override
        public int read(byte[] into, int off, int len) throws IOException {

            while (!eof && pending.available() <= 0) {

                // we also need to go here for len <= 0, because pending may be at
                // EOF in which case it would return -1 instead of 0

                long requestOffset;
                if (unconfirmedReads.isEmpty()) {
                    requestOffset = currentOffset;
                }
                else {
                    final UnconfirmedRead lastRequest = unconfirmedReads.getLast();
                    requestOffset = lastRequest.offset + lastRequest.length;
                }
                while (unconfirmedReads.size() <= maxUnconfirmedReads) {
                    // Send read requests as long as there is no EOF and we have not reached the maximum parallelism
                    int reqLen = Math.min(Math.max(1024, len), maxReadLength);
                    if (readAheadLimit > requestOffset) {
                        long remaining = readAheadLimit - requestOffset;
                        if (reqLen > remaining) {
                            reqLen = (int) remaining;
                        }
                    }
                    unconfirmedReads.add(new UnconfirmedRead(requestOffset, reqLen));
                    requestOffset += reqLen;
                    if (requestOffset >= readAheadLimit) {
                        break;
                    }
                }

                if (!retrieveUnconfirmedRead(true /*blocking*/)) {

                    // this may happen if we change prefetch strategy
                    // currently, we should never get here...

                    throw new IllegalStateException("Could not retrieve data for pending read request");
                }
            }

            return pending.read(into, off, len);
        }

        @Override
        public int available() throws IOException {
            boolean lastRead = true;
            while (!eof && (pending.available() <= 0) && lastRead) {
                lastRead = retrieveUnconfirmedRead(false /*blocking*/);
            }
            return pending.available();
        }
    }
}

