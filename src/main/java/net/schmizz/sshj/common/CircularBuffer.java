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
package net.schmizz.sshj.common;

public class CircularBuffer<T extends CircularBuffer<T>> {

    public static class CircularBufferException
            extends SSHException {

        public CircularBufferException(String message) {
            super(message);
        }
    }

    public static final class PlainCircularBuffer
            extends CircularBuffer<PlainCircularBuffer> {

        public PlainCircularBuffer(int size, int maxSize) {
            super(size, maxSize);
        }
    }

    /**
     * Maximum size of the internal array (one plus the maximum capacity of the buffer).
     */
    private final int maxSize;
    /**
     * Internal array for the data. All bytes minus one can be used to avoid empty vs full ambiguity when rpos == wpos.
     */
    private byte[] data;
    /**
     * Next read position. Wraps around the end of the internal array. When it reaches wpos, the buffer becomes empty.
     * Can take the value data.length, which is equivalent to 0.
     */
    private int rpos;
    /**
     * Next write position. Wraps around the end of the internal array. If it is equal to rpos, then the buffer is
     * empty; the code does not allow wpos to reach rpos from the left. This implies that the buffer can store up to
     * data.length - 1 bytes. Can take the value data.length, which is equivalent to 0.
     */
    private int wpos;

    /**
     * Determines the size to which to grow the internal array.
     */
    private int getNextSize(int currentSize) {
        // Use next power of 2.
        int nextSize = 1;
        while (nextSize < currentSize) {
            nextSize <<= 1;
            if (nextSize <= 0) {
                return maxSize;
            }
        }
        return Math.min(nextSize, maxSize); // limit to max size
    }

    /**
     * Creates a new circular buffer of the given size. The capacity of the buffer is one less than the size/
     */
    public CircularBuffer(int size, int maxSize) {
        this.maxSize = maxSize;
        if (size > maxSize) {
            throw new IllegalArgumentException(
                String.format("Initial requested size %d larger than maximum size %d", size, maxSize));
        }
        int initialSize = getNextSize(size);
        this.data = new byte[initialSize];
        this.rpos = 0;
        this.wpos = 0;
    }

    /**
     * Data available in the buffer for reading.
     */
    public int available() {
        int available = wpos - rpos;
        return available >= 0 ? available : available + data.length; // adjust if wpos is left of rpos
    }

    private void ensureAvailable(int a)
            throws CircularBufferException {
        if (available() < a) {
            throw new CircularBufferException("Underflow");
        }
    }

    /**
     * Returns how many more bytes this buffer can receive.
     */
    public int maxPossibleRemainingCapacity() {
        // Remaining capacity is one less than remaining space to ensure that wpos does not reach rpos from the left.
        int remaining = rpos - wpos - 1;
        if (remaining < 0) {
            remaining += data.length; // adjust if rpos is left of wpos
        }
        // Add the maximum amount the internal array can grow.
        return remaining + maxSize - data.length;
    }

    /**
     * If the internal array does not have room for "capacity" more bytes, resizes the array to make that room.
     */
    void ensureCapacity(int capacity) throws CircularBufferException {
        int available = available();
        int remaining = data.length - available;
        // If capacity fits exactly in the remaining space, expand it; otherwise, wpos would reach rpos from the left.
        if (remaining <= capacity) {
            int neededSize = available + capacity + 1;
            int nextSize = getNextSize(neededSize);
            if (nextSize < neededSize) {
                throw new CircularBufferException("Attempted overflow");
            }
            byte[] tmp = new byte[nextSize];
            // Copy data to the beginning of the new array.
            if (wpos >= rpos) {
                System.arraycopy(data, rpos, tmp, 0, available);
                wpos -= rpos; // wpos must be relative to the new rpos, which will be 0
            } else {
                int tail = data.length - rpos;
                System.arraycopy(data, rpos, tmp, 0, tail); // segment right of rpos
                System.arraycopy(data, 0, tmp, tail, wpos); // segment left of wpos
                wpos += tail; // wpos must be relative to the new rpos, which will be 0
            }
            rpos = 0;
            data = tmp;
        }
    }

    /**
     * Reads data from this buffer into the provided array.
     */
    public void readRawBytes(byte[] destination, int offset, int length) throws CircularBufferException {
        ensureAvailable(length);

        int rposNext = rpos + length;
        if (rposNext <= data.length) {
            System.arraycopy(data, rpos, destination, offset, length);
        } else {
            int tail = data.length - rpos;
            System.arraycopy(data, rpos, destination, offset, tail); // segment right of rpos
            rposNext = length - tail; // rpos wraps around the end of the buffer
            System.arraycopy(data, 0, destination, offset + tail, rposNext); // remainder
        }
        // This can make rpos equal data.length, which has the same effect as wpos being 0.
        rpos = rposNext;
    }

    /**
     * Writes data to this buffer from the provided array.
     */
    @SuppressWarnings("unchecked")
    public T putRawBytes(byte[] source, int offset, int length) throws CircularBufferException {
        ensureCapacity(length);

        int wposNext = wpos + length;
        if (wposNext <= data.length) {
            System.arraycopy(source, offset, data, wpos, length);
        } else {
            int tail = data.length - wpos;
            System.arraycopy(source, offset, data, wpos, tail); // segment right of wpos
            wposNext = length - tail; // wpos wraps around the end of the buffer
            System.arraycopy(source, offset + tail, data, 0, wposNext); // remainder
        }
        // This can make wpos equal data.length, which has the same effect as wpos being 0.
        wpos = wposNext;

        return (T) this;
    }

    // Used only for testing.
    int length() {
        return data.length;
    }

    @Override
    public String toString() {
        return "CircularBuffer [rpos=" + rpos + ", wpos=" + wpos + ", size=" + data.length + "]";
    }

}
