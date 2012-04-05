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

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;

public class RandomAccessRemoteFile
        implements DataInput, DataOutput {


    private final byte[] singleByte = new byte[1];

    private final RemoteFile rf;

    private long fp;

    public RandomAccessRemoteFile(RemoteFile rf) {
        this.rf = rf;
    }

    public long getFilePointer() {
        return fp;
    }

    public void seek(long fp) {
        this.fp = fp;
    }

    public int read()
            throws IOException {
        return read(singleByte, 0, 1) == -1 ? -1 : singleByte[0];
    }

    public int read(byte[] b)
            throws IOException {
        return read(b, 0, b.length);
    }

    public int read(byte[] b, int off, int len)
            throws IOException {
        final int count = rf.read(fp, b, off, len);
        fp += count;
        return count;
    }

    @Override
    public boolean readBoolean()
            throws IOException {
        final int ch = read();
        if (ch < 0)
            throw new EOFException();
        return (ch != 0);
    }

    @Override
    public byte readByte()
            throws IOException {
        final int ch = this.read();
        if (ch < 0)
            throw new EOFException();
        return (byte) (ch);
    }

    @Override
    public char readChar()
            throws IOException {
        final int ch1 = this.read();
        final int ch2 = this.read();
        if ((ch1 | ch2) < 0)
            throw new EOFException();
        return (char) ((ch1 << 8) + ch2);
    }

    @Override
    public double readDouble()
            throws IOException {
        return Double.longBitsToDouble(readLong());
    }

    @Override
    public float readFloat()
            throws IOException {
        return Float.intBitsToFloat(readInt());
    }

    @Override
    public void readFully(byte[] b)
            throws IOException {
        readFully(b, 0, b.length);
    }

    @Override
    public void readFully(byte[] b, int off, int len)
            throws IOException {
        int n = 0;
        do {
            int count = read(b, off + n, len - n);
            if (count < 0)
                throw new EOFException();
            n += count;
        } while (n < len);
    }

    @Override
    public int readInt()
            throws IOException {
        final int ch1 = read();
        final int ch2 = read();
        final int ch3 = read();
        final int ch4 = read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new EOFException();
        return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + ch4);
    }

    @Override
    public String readLine()
            throws IOException {
        StringBuffer input = new StringBuffer();
        int c = -1;
        boolean eol = false;

        while (!eol)
            switch (c = read()) {
                case -1:
                case '\n':
                    eol = true;
                    break;
                case '\r':
                    eol = true;
                    long cur = getFilePointer();
                    if ((read()) != '\n')
                        seek(cur);
                    break;
                default:
                    input.append((char) c);
                    break;
            }

        if ((c == -1) && (input.length() == 0))
            return null;
        return input.toString();
    }

    @Override
    public long readLong()
            throws IOException {
        return ((long) (readInt()) << 32) + (readInt() & 0xFFFFFFFFL);
    }

    @Override
    public short readShort()
            throws IOException {
        final int ch1 = this.read();
        final int ch2 = this.read();
        if ((ch1 | ch2) < 0)
            throw new EOFException();
        return (short) ((ch1 << 8) + ch2);
    }

    @Override
    public String readUTF()
            throws IOException {
        return DataInputStream.readUTF(this);
    }

    @Override
    public int readUnsignedByte()
            throws IOException {
        final int ch = this.read();
        if (ch < 0)
            throw new EOFException();
        return ch;
    }

    @Override
    public int readUnsignedShort()
            throws IOException {
        final int ch1 = this.read();
        final int ch2 = this.read();
        if ((ch1 | ch2) < 0)
            throw new EOFException();
        return (ch1 << 8) + ch2;
    }

    @Override
    public int skipBytes(int n)
            throws IOException {
        if (n <= 0)
            return 0;
        final long pos = getFilePointer();
        final long len = rf.length();
        long newpos = pos + n;
        if (newpos > len)
            newpos = len;
        seek(newpos);

        /* return the actual number of bytes skipped */
        return (int) (newpos - pos);
    }

    @Override
    public void write(int i)
            throws IOException {
        singleByte[0] = (byte) i;
        write(singleByte);
    }

    @Override
    public void write(byte[] b)
            throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len)
            throws IOException {
        rf.write(fp, b, off, len);
        fp += (len - off);
    }

    @Override
    public void writeBoolean(boolean v)
            throws IOException {
        write(v ? 1 : 0);
    }

    @Override
    public void writeByte(int v)
            throws IOException {
        write(v);
    }

    @Override
    public void writeBytes(String s)
            throws IOException {
        final byte[] b = s.getBytes();
        write(b, 0, b.length);
    }

    @Override
    public void writeChar(int v)
            throws IOException {
        write((v >>> 8) & 0xFF);
        write(v & 0xFF);
    }

    @Override
    public void writeChars(String s)
            throws IOException {
        final int clen = s.length();
        final int blen = 2 * clen;
        final byte[] b = new byte[blen];
        final char[] c = new char[clen];
        s.getChars(0, clen, c, 0);
        for (int i = 0, j = 0; i < clen; i++) {
            b[j++] = (byte) (c[i] >>> 8);
            b[j++] = (byte) c[i];
        }
        write(b, 0, blen);
    }

    @Override
    public void writeDouble(double v)
            throws IOException {
        writeLong(Double.doubleToLongBits(v));
    }

    @Override
    public void writeFloat(float v)
            throws IOException {
        writeInt(Float.floatToIntBits(v));
    }

    @Override
    public void writeInt(int v)
            throws IOException {
        write((v >>> 24) & 0xFF);
        write((v >>> 16) & 0xFF);
        write((v >>> 8) & 0xFF);
        write(v & 0xFF);
    }

    @Override
    public void writeLong(long v)
            throws IOException {
        write((int) (v >>> 56) & 0xFF);
        write((int) (v >>> 48) & 0xFF);
        write((int) (v >>> 40) & 0xFF);
        write((int) (v >>> 32) & 0xFF);
        write((int) (v >>> 24) & 0xFF);
        write((int) (v >>> 16) & 0xFF);
        write((int) (v >>> 8) & 0xFF);
        write((int) v & 0xFF);
    }

    @Override
    public void writeShort(int v)
            throws IOException {
        write((v >>> 8) & 0xFF);
        write(v & 0xFF);
    }

    @Override
    public void writeUTF(String str)
            throws IOException {
        final DataOutputStream dos = new DataOutputStream(rf.new RemoteFileOutputStream(fp));
        try {
            dos.writeUTF(str);
        } finally {
            dos.close();
        }
        fp += dos.size();
    }

}
