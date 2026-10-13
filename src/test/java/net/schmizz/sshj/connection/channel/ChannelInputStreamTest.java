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
package net.schmizz.sshj.connection.channel;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.transport.Transport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.SocketTimeoutException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class ChannelInputStreamTest {

    private Channel chan;
    private Window.Local win;
    private ScheduledExecutorService scheduler;

    @BeforeEach
    void setUp() {
        Config config = mock(Config.class);
        when(config.getMaxCircularBufferSize()).thenReturn(16 * 1024 * 1024);

        Transport trans = mock(Transport.class);
        when(trans.getConfig()).thenReturn(config);

        chan = mock(Channel.class);
        when(chan.getLoggerFactory()).thenReturn(LoggerFactory.DEFAULT);
        when(chan.getLocalMaxPacketSize()).thenReturn(32768);
        when(chan.getAutoExpand()).thenReturn(false);

        win = new Window.Local(2097152, 32768, LoggerFactory.DEFAULT);
        scheduler = Executors.newSingleThreadScheduledExecutor();
    }

    @AfterEach
    void tearDown() {
        scheduler.shutdownNow();
    }

    @Test
    void timeoutFiresWhenNoDataArrives() {
        ChannelInputStream stream = newStream(100);
        assertThrows(SocketTimeoutException.class, () -> stream.read(new byte[8], 0, 8));
    }

    @Test
    void eofBeforeTimeoutReturnsMinusOne() throws Exception {
        ChannelInputStream stream = newStream(500);
        scheduleAfter(50, stream::eof);
        assertEquals(-1, stream.read(new byte[8], 0, 8));
    }

    @Test
    void dataArrivesBeforeTimeout() throws Exception {
        ChannelInputStream stream = newStream(500);
        byte[] data = "hello".getBytes();
        scheduleAfter(50, () -> stream.receive(data, 0, data.length));

        byte[] buf = new byte[data.length];
        int read = stream.read(buf, 0, buf.length);
        assertEquals(data.length, read);
        assertArrayEquals(data, buf);
    }

    @Test
    void notifyErrorThrowsBeforeTimeout() throws Exception {
        ChannelInputStream stream = newStream(500);
        SSHException error = new SSHException("remote error");
        scheduleAfter(50, () -> stream.notifyError(error));

        SSHException thrown = assertThrows(SSHException.class, () -> stream.read(new byte[8], 0, 8));
        assertSame(error, thrown);
    }

    @Test
    void zeroTimeoutBlocksUntilEof() throws Exception {
        ChannelInputStream stream = newStream(0);
        scheduleAfter(100, stream::eof);
        assertEquals(-1, stream.read(new byte[8], 0, 8));
    }

    private ChannelInputStream newStream(int timeoutMs) {
        Config config = mock(Config.class);
        when(config.getMaxCircularBufferSize()).thenReturn(16 * 1024 * 1024);
        Transport trans = mock(Transport.class);
        when(trans.getConfig()).thenReturn(config);
        return new ChannelInputStream(chan, trans, win, timeoutMs);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private void scheduleAfter(long delayMs, ThrowingRunnable action) {
        scheduler.schedule(() -> {
            try {
                action.run();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, delayMs, TimeUnit.MILLISECONDS);
    }
}
