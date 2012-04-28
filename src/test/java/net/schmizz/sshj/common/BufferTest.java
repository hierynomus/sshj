package net.schmizz.sshj.common;

import static org.junit.Assert.fail;

import net.schmizz.sshj.common.Buffer.PlainBuffer;

import org.junit.Test;

public class BufferTest {

    // Issue 72: previously, it entered an infinite loop trying to establish the buffer size
    @Test
    public void shouldThrowOnTooLargeCapacity() {
        PlainBuffer buffer = new PlainBuffer();
        try {
            buffer.ensureCapacity(Integer.MAX_VALUE);
            fail("Allegedly ensured buffer capacity of size " + Integer.MAX_VALUE);
        } catch (IllegalArgumentException e) {
            // success
        }
    }

    // Issue 72: previously, it entered an infinite loop trying to establish the buffer size
    @Test
    public void shouldThrowOnTooLargeInitialCapacity() {
        try {
            new PlainBuffer(Integer.MAX_VALUE);
            fail("Allegedly created buffer with size " + Integer.MAX_VALUE);
        } catch (IllegalArgumentException e) {
            // success
        }
    }
}
