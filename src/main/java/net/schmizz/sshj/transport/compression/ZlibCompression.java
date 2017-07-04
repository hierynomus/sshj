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

import com.jcraft.jzlib.Deflater;
import com.jcraft.jzlib.GZIPException;
import com.jcraft.jzlib.Inflater;
import com.jcraft.jzlib.JZlib;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.transport.TransportException;

/** ZLib based Compression. */
public class ZlibCompression
        implements Compression {

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
        try {
            switch (mode) {
                case DEFLATE:
                    deflater = new Deflater(JZlib.Z_DEFAULT_COMPRESSION);
                    break;
                case INFLATE:
                    inflater = new Inflater();
                    break;
                default:
                    assert false;
            }
        } catch (GZIPException gze) {

        }
    }

    @Override
    public boolean isDelayed() {
        return false;
    }

    @Override
    public void compress(Buffer buffer) {
        deflater.setNextIn(buffer.array());
        deflater.setNextInIndex(buffer.rpos());
        deflater.setAvailIn(buffer.available());
        buffer.wpos(buffer.rpos());
        do {
            deflater.setNextOut(tempBuf);
            deflater.setNextOutIndex(0);
            deflater.setAvailOut(BUF_SIZE);
            final int status = deflater.deflate(JZlib.Z_PARTIAL_FLUSH);
            if (status == JZlib.Z_OK) {
                buffer.putRawBytes(tempBuf, 0, BUF_SIZE - deflater.getAvailOut());
            } else {
                throw new SSHRuntimeException("compress: deflate returned " + status);
            }
        } while (deflater.getAvailOut() == 0);
    }


    @Override
    public void uncompress(Buffer from, Buffer to)
            throws TransportException {
        inflater.setNextIn(from.array());
        inflater.setNextInIndex(from.rpos());
        inflater.setAvailIn(from.available());
        while (true) {
            inflater.setNextOut(tempBuf);
            inflater.setNextOutIndex(0);
            inflater.setAvailOut(BUF_SIZE);
            final int status = inflater.inflate(JZlib.Z_PARTIAL_FLUSH);
            switch (status) {
                case JZlib.Z_OK:
                    to.putRawBytes(tempBuf, 0, BUF_SIZE - inflater.getAvailOut());
                    break;
                case JZlib.Z_BUF_ERROR:
                    return;
                default:
                    throw new TransportException(DisconnectReason.COMPRESSION_ERROR, "uncompress: inflate returned " + status);
            }
        }
    }

}
