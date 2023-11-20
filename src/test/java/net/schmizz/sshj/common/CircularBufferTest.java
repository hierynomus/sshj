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

import static org.junit.jupiter.api.Assertions.*;

import net.schmizz.sshj.common.CircularBuffer.CircularBufferException;
import net.schmizz.sshj.common.CircularBuffer.PlainCircularBuffer;
import org.junit.jupiter.api.Test;

public class CircularBufferTest {

    @Test
    public void shouldStoreDataCorrectlyWithoutResizing() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(256, Integer.MAX_VALUE);

        byte[] dataToWrite = getData(500);
        buffer.putRawBytes(dataToWrite, 0, 100);
        buffer.putRawBytes(dataToWrite, 100, 100);

        byte[] dataToRead = new byte[500];
        buffer.readRawBytes(dataToRead, 0, 80);
        buffer.readRawBytes(dataToRead, 80, 80);

        buffer.putRawBytes(dataToWrite, 200, 100);
        buffer.readRawBytes(dataToRead, 160, 80);

        buffer.putRawBytes(dataToWrite, 300, 100);
        buffer.readRawBytes(dataToRead, 240, 80);

        buffer.putRawBytes(dataToWrite, 400, 100);
        buffer.readRawBytes(dataToRead, 320, 80);
        buffer.readRawBytes(dataToRead, 400, 100);

        assertEquals(256, buffer.length());
        assertArrayEquals(dataToWrite, dataToRead);
    }

    @Test
    public void shouldStoreDataCorrectlyWithResizing() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, Integer.MAX_VALUE);

        byte[] dataToWrite = getData(500);
        buffer.putRawBytes(dataToWrite, 0, 100);
        buffer.putRawBytes(dataToWrite, 100, 100);

        byte[] dataToRead = new byte[500];
        buffer.readRawBytes(dataToRead, 0, 80);
        buffer.readRawBytes(dataToRead, 80, 80);

        buffer.putRawBytes(dataToWrite, 200, 100);
        buffer.readRawBytes(dataToRead, 160, 80);

        buffer.putRawBytes(dataToWrite, 300, 100);
        buffer.readRawBytes(dataToRead, 240, 80);

        buffer.putRawBytes(dataToWrite, 400, 100);
        buffer.readRawBytes(dataToRead, 320, 80);

        buffer.readRawBytes(dataToRead, 400, 100);

        assertEquals(256, buffer.length());
        assertArrayEquals(dataToWrite, dataToRead);
    }

    @Test
    public void shouldNotOverflowWhenWritingFullLengthToTheEnd() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, Integer.MAX_VALUE);

        byte[] dataToWrite = getData(64);
        buffer.putRawBytes(dataToWrite, 0, dataToWrite.length); // should write to the end

        assertEquals(64, buffer.available());
        assertEquals(64 * 2, buffer.length());
    }

    @Test
    public void shouldNotOverflowWhenWritingFullLengthWrapsAround() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, Integer.MAX_VALUE);

        // Move 1 byte forward.
        buffer.putRawBytes(new byte[1], 0, 1);
        buffer.readRawBytes(new byte[1], 0, 1);

        // Force writes to wrap around.
        byte[] dataToWrite = getData(64);
        buffer.putRawBytes(dataToWrite, 0, dataToWrite.length); // should wrap around the end

        assertEquals(64, buffer.available());
        assertEquals(64 * 2, buffer.length());
    }

    @Test
    public void shouldAllowWritingMaxCapacityFromZero() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, 64);

        // Max capacity is always one less than the buffer size.
        int maxCapacity = buffer.maxPossibleRemainingCapacity();
        assertEquals(buffer.length() - 1, maxCapacity);

        byte[] dataToWrite = getData(maxCapacity);
        buffer.putRawBytes(dataToWrite, 0, dataToWrite.length);

        assertEquals(dataToWrite.length, buffer.available());
        assertEquals(64, buffer.length());
    }

    @Test
    public void shouldAllowWritingMaxRemainingCapacity() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, 64);

        final int initiallyWritten = 10;
        buffer.putRawBytes(new byte[initiallyWritten], 0, initiallyWritten);

        // Max remaining capacity is always one less than the remaining buffer size.
        int maxRemainingCapacity = buffer.maxPossibleRemainingCapacity();
        assertEquals(buffer.length() - 1 - initiallyWritten, maxRemainingCapacity);

        byte[] dataToWrite = getData(maxRemainingCapacity);
        buffer.putRawBytes(dataToWrite, 0, dataToWrite.length);

        assertEquals(dataToWrite.length + initiallyWritten, buffer.available());
        assertEquals(64, buffer.length());
    }

    @Test
    public void shouldAllowWritingMaxRemainingCapacityAfterWrappingAround() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, 64);

        // Cause the internal write pointer to wrap around and be left of the read pointer.
        final int initiallyWritten = 40;
        buffer.putRawBytes(new byte[initiallyWritten], 0, initiallyWritten);
        buffer.readRawBytes(new byte[initiallyWritten], 0, initiallyWritten);
        buffer.putRawBytes(new byte[initiallyWritten], 0, initiallyWritten);

        // Max remaining capacity is always one less than the remaining buffer size.
        int maxRemainingCapacity = buffer.maxPossibleRemainingCapacity();
        assertEquals(buffer.length() - 1 - initiallyWritten, maxRemainingCapacity);

        byte[] dataToWrite = getData(maxRemainingCapacity);
        buffer.putRawBytes(dataToWrite, 0, dataToWrite.length);

        assertEquals(dataToWrite.length + initiallyWritten, buffer.available());
        assertEquals(64, buffer.length());
    }

    @Test
    public void shouldOverflowWhenWritingOverMaxRemainingCapacity() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, 64);

        final int initiallyWritten = 10;
        buffer.putRawBytes(new byte[initiallyWritten], 0, initiallyWritten);

        // Max remaining capacity is always one less than the remaining buffer size.
        int maxRemainingCapacity = buffer.maxPossibleRemainingCapacity();
        assertEquals(buffer.length() - 1 - initiallyWritten, maxRemainingCapacity);

        byte[] dataToWrite = getData(maxRemainingCapacity + 1);
        assertThrows(CircularBufferException.class, () -> buffer.putRawBytes(dataToWrite, 0, dataToWrite.length));
    }

    @Test
    public void shouldThrowWhenReadingEmptyBuffer() {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, Integer.MAX_VALUE);
        assertThrows(CircularBufferException.class, () -> buffer.readRawBytes(new byte[1], 0, 1));
    }

    @Test
    public void shouldThrowWhenReadingMoreThanAvailable() throws CircularBufferException {
        PlainCircularBuffer buffer = new PlainCircularBuffer(64, Integer.MAX_VALUE);
        buffer.putRawBytes(new byte[1], 0, 1);
        assertThrows(CircularBufferException.class, () -> buffer.readRawBytes(new byte[2], 0, 2));
    }

    @Test
    public void shouldThrowOnAboveMaximumInitialSize() {
        assertThrows(IllegalArgumentException.class, () -> new PlainCircularBuffer(65, 64));
    }

    @Test
    public void shouldThrowOnMaximumInitialSize() {
        assertThrows(IllegalArgumentException.class, () -> new PlainCircularBuffer(Integer.MAX_VALUE, 64));
    }

    @Test
    public void shouldAllowFullCapacity() throws CircularBufferException {
        int maxSize = 1024;
        PlainCircularBuffer buffer = new PlainCircularBuffer(256, maxSize);
        buffer.ensureCapacity(maxSize - 1);
        assertEquals(maxSize - 1, buffer.maxPossibleRemainingCapacity());
    }

    @Test
    public void shouldThrowOnTooLargeRequestedCapacity() {
        int maxSize = 1024;
        PlainCircularBuffer buffer = new PlainCircularBuffer(256, maxSize);
        assertThrows(CircularBufferException.class, () -> buffer.ensureCapacity(maxSize));
    }

    private static byte[] getData(int length) {
        byte[] data = new byte[length];
        byte nextValue = 0;
        for (int i = 0; i < length; ++i) {
            data[i] = nextValue++;
        }
        return data;
    }
}
