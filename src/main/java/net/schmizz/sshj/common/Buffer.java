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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */
package net.schmizz.sshj.common;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;

public class Buffer<T extends Buffer<T>> {

    public static class BufferException
            extends SSHException {

        public BufferException(String message) {
            super(message);
        }
    }

    public static final class PlainBuffer
            extends Buffer<PlainBuffer> {

        public PlainBuffer() {
            super();
        }

        public PlainBuffer(Buffer<?> from) {
            super(from);
        }

        public PlainBuffer(byte[] b) {
            super(b);
        }

        public PlainBuffer(int size) {
            super(size);
        }
    }

    /** The default size for a {@code Buffer} (256 bytes) */
    public static final int DEFAULT_SIZE = 256;

    /** The maximum valid size of buffer (i.e. biggest power of two that can be represented as an int - 2^30) */
    public static final int MAX_SIZE = (1 << 30); 

    protected static int getNextPowerOf2(int i) {
        int j = 1;
        while (j < i) {
            j <<= 1;
            if (j <= 0) throw new IllegalArgumentException("Cannot get next power of 2; "+i+" is too large"); 
        }
        return j;
    }

    protected byte[] data;
    protected int rpos;
    protected int wpos;

    /** @see #DEFAULT_SIZE */
    public Buffer() {
        this(DEFAULT_SIZE);
    }

    public Buffer(Buffer<?> from) {
        data = new byte[(wpos = from.wpos - from.rpos)];
        System.arraycopy(from.data, from.rpos, data, 0, wpos);
    }

    public Buffer(byte[] data) {
        this(data, true);
    }

    public Buffer(int size) {
        this(new byte[getNextPowerOf2(size)], false);
    }

    private Buffer(byte[] data, boolean read) {
        this.data = data;
        rpos = 0;
        wpos = read ? data.length : 0;
    }

    public byte[] array() {
        return data;
    }

    public int available() {
        return wpos - rpos;
    }

    /** Resets this buffer. The object becomes ready for reuse. */
    public void clear() {
        rpos = 0;
        wpos = 0;
    }

    public int rpos() {
        return rpos;
    }

    public void rpos(int rpos) {
        this.rpos = rpos;
    }

    public int wpos() {
        return wpos;
    }

    public void wpos(int wpos) {
        ensureCapacity(wpos - this.wpos);
        this.wpos = wpos;
    }

    protected void ensureAvailable(int a)
            throws BufferException {
        if (available() < a)
            throw new BufferException("Underflow");
    }

    public void ensureCapacity(int capacity) {
        if (data.length - wpos < capacity) {
            int cw = wpos + capacity;
            byte[] tmp = new byte[getNextPowerOf2(cw)];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
    }

    /** Compact this {@link SSHPacket} */
    public void compact() {
        System.err.println("COMPACTING");
        if (available() > 0)
            System.arraycopy(data, rpos, data, 0, wpos - rpos);
        wpos -= rpos;
        rpos = 0;
    }

    public byte[] getCompactData() {
        final int len = available();
        if (len > 0) {
            byte[] b = new byte[len];
            System.arraycopy(data, rpos, b, 0, len);
            return b;
        } else
            return new byte[0];
    }

    /**
     * Read an SSH boolean byte
     *
     * @return the {@code true} or {@code false} value read
     */
    public boolean readBoolean()
            throws BufferException {
        return readByte() != 0;
    }

    /**
     * Puts an SSH boolean value
     *
     * @param b the value
     *
     * @return this
     */
    public T putBoolean(boolean b) {
        return putByte(b ? (byte) 1 : (byte) 0);
    }

    /**
     * Read a byte from the buffer
     *
     * @return the byte read
     */
    public byte readByte()
            throws BufferException {
        ensureAvailable(1);
        return data[rpos++];
    }

    /**
     * Writes a single byte into this buffer
     *
     * @param b
     *
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putByte(byte b) {
        ensureCapacity(1);
        data[wpos++] = b;
        return (T) this;
    }

    /**
     * Read an SSH byte-array
     *
     * @return the byte-array read
     */
    public byte[] readBytes()
            throws BufferException {
        int len = readUInt32AsInt();
        if (len < 0 || len > 32768)
            throw new BufferException("Bad item length: " + len);
        byte[] b = new byte[len];
        readRawBytes(b);
        return b;
    }

    /**
     * Writes Java byte-array as an SSH byte-array
     *
     * @param b Java byte-array
     *
     * @return this
     */
    public T putBytes(byte[] b) {
        return putBytes(b, 0, b.length);
    }

    /**
     * Writes Java byte-array as an SSH byte-array
     *
     * @param b   Java byte-array
     * @param off offset
     * @param len length
     *
     * @return this
     */
    public T putBytes(byte[] b, int off, int len) {
        return putUInt32(len - off).putRawBytes(b, off, len);
    }

    public void readRawBytes(byte[] buf)
            throws BufferException {
        readRawBytes(buf, 0, buf.length);
    }

    public void readRawBytes(byte[] buf, int off, int len)
            throws BufferException {
        ensureAvailable(len);
        System.arraycopy(data, rpos, buf, off, len);
        rpos += len;
    }

    public T putRawBytes(byte[] d) {
        return putRawBytes(d, 0, d.length);
    }

    @SuppressWarnings("unchecked")
    public T putRawBytes(byte[] d, int off, int len) {
        ensureCapacity(len);
        System.arraycopy(d, off, data, wpos, len);
        wpos += len;
        return (T) this;
    }

    /**
     * Copies the contents of provided buffer into this buffer
     *
     * @param buffer the {@code Buffer} to copy
     *
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putBuffer(Buffer<? extends Buffer<?>> buffer) {
        if (buffer != null) {
            int r = buffer.available();
            ensureCapacity(r);
            System.arraycopy(buffer.data, buffer.rpos, data, wpos, r);
            wpos += r;
        }
        return (T) this;
    }

    public int readUInt32AsInt()
            throws BufferException {
        return (int) readUInt32();
    }

    public long readUInt32()
            throws BufferException {
        ensureAvailable(4);
        return data[rpos++] << 24 & 0xff000000L |
                data[rpos++] << 16 & 0x00ff0000L |
                data[rpos++] << 8 & 0x0000ff00L |
                data[rpos++] & 0x000000ffL;
    }

    /**
     * Writes a uint32 integer
     *
     * @param uint32
     *
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putUInt32(long uint32) {
        ensureCapacity(4);
        if (uint32 < 0 || uint32 > 0xffffffffL)
            throw new RuntimeException("Invalid value: " + uint32);
        data[wpos++] = (byte) (uint32 >> 24);
        data[wpos++] = (byte) (uint32 >> 16);
        data[wpos++] = (byte) (uint32 >> 8);
        data[wpos++] = (byte) uint32;
        return (T) this;
    }

    /**
     * Read an SSH multiple-precision integer
     *
     * @return the MP integer as a {@code BigInteger}
     */
    public BigInteger readMPInt()
            throws BufferException {
        return new BigInteger(readBytes());
    }

    public T putMPInt(BigInteger bi) {
        final byte[] asBytes = bi.toByteArray();
        putUInt32(asBytes.length);
        return putRawBytes(asBytes);
    }

    public long readUInt64()
            throws BufferException {
        long uint64 = (readUInt32() << 32) + (readUInt32() & 0xffffffffL);
        if (uint64 < 0)
            throw new BufferException("Cannot handle values > Long.MAX_VALUE");
        return uint64;
    }

    @SuppressWarnings("unchecked")
    public T putUInt64(long uint64) {
        if (uint64 < 0)
            throw new RuntimeException("Invalid value: " + uint64);
        data[wpos++] = (byte) (uint64 >> 56);
        data[wpos++] = (byte) (uint64 >> 48);
        data[wpos++] = (byte) (uint64 >> 40);
        data[wpos++] = (byte) (uint64 >> 32);
        data[wpos++] = (byte) (uint64 >> 24);
        data[wpos++] = (byte) (uint64 >> 16);
        data[wpos++] = (byte) (uint64 >> 8);
        data[wpos++] = (byte) uint64;
        return (T) this;
    }

    /**
     * Reads an SSH string
     *
     * @return the string as a Java {@code String}
     */
    public String readString()
            throws BufferException {
        int len = readUInt32AsInt();
        if (len < 0 || len > 32768)
            throw new BufferException("Bad item length: " + len);
        ensureAvailable(len);
        String s;
        try {
            s = new String(data, rpos, len, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new SSHRuntimeException(e);
        }
        rpos += len;
        return s;
    }

    /**
     * Reads an SSH string
     *
     * @return the string as a byte-array
     */
    public byte[] readStringAsBytes()
            throws BufferException {
        return readBytes();
    }

    public T putString(byte[] str) {
        return putBytes(str);
    }

    public T putString(byte[] str, int offset, int len) {
        return putBytes(str, offset, len);
    }

    public T putString(String string) {
        return putString(string.getBytes(IOUtils.UTF8));
    }

    /**
     * Writes a char-array as an SSH string and then blanks it out.
     * <p/>
     * This is useful when a plaintext password needs to be sent. If {@code str} is {@code null}, an empty string is
     * written.
     *
     * @param str (null-ok) the string as a character array
     *
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putSensitiveString(char[] str) {
        if (str == null)
            return putString("");
        putUInt32(str.length);
        ensureCapacity(str.length);
        for (char c : str)
            data[wpos++] = (byte) c;
        Arrays.fill(str, ' ');
        return (T) this;
    }

    public PublicKey readPublicKey()
            throws BufferException {
        try {
            final String type = readString();
            return KeyType.fromString(type).readPubKeyFromBuffer(type, this);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public T putPublicKey(PublicKey key) {
        KeyType.fromKey(key).putPubKeyIntoBuffer(key, this);
        return (T) this;
    }

    public T putSignature(String sigFormat, byte[] sigData) {
        final byte[] sig = new PlainBuffer().putString(sigFormat).putBytes(sigData).getCompactData();
        return putString(sig);
    }

    /**
     * Gives a readable snapshot of the buffer in hex. This is useful for debugging.
     *
     * @return snapshot of the buffer as a hex string with each octet delimited by a space
     */
    public String printHex() {
        return ByteArrayUtils.printHex(array(), rpos(), available());
    }

    @Override
    public String toString() {
        return "Buffer [rpos=" + rpos + ", wpos=" + wpos + ", size=" + data.length + "]";
    }

}
