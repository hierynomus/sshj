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
package net.schmizz.sshj.transport.compression;

import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.compression.Compression;

public class ZlibCompression implements Compression {

    /** Named factory for the ZLib Compression. */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Compression> {

        @Override
        public Compression create() {
            return new ZlibCompression();
        }

        @Override
        public String getName() {
            return "zlib";
        }
    }

    private static final int BUF_SIZE = 4096;

    private final byte[] tempBuf = new byte[BUF_SIZE];

    private Deflater deflater;
    private Inflater inflater;

    @Override
    public void init(Mode mode) {
        switch (mode) {
            case DEFLATE:
                deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
                break;
            case INFLATE:
                inflater = new Inflater();
                break;
            default:
                assert false;
        }
    }

    @Override
    public boolean isDelayed() {
        return false;
    }

    @Override
    public void compress(Buffer buffer) {
        deflater.setInput(buffer.array(), buffer.rpos(), buffer.available());
        buffer.wpos(buffer.rpos());
        do {
            final int len = deflater.deflate(tempBuf, 0, BUF_SIZE, Deflater.SYNC_FLUSH);
            buffer.putRawBytes(tempBuf, 0, len);
        } while (!deflater.needsInput());
    }

    @Override
    public void uncompress(Buffer from, Buffer to)
            throws TransportException {
        inflater.setInput(from.array(), from.rpos(), from.available());
        while (true) {
            try {
                int len = inflater.inflate(tempBuf, 0, BUF_SIZE);
                if(len > 0) {
                    to.putRawBytes(tempBuf, 0, len);
                } else {
                    return;
                }
            } catch (DataFormatException e) {
                throw new TransportException(DisconnectReason.COMPRESSION_ERROR, "uncompress: inflate returned " + e.getMessage());
            }
        }
    }

}
