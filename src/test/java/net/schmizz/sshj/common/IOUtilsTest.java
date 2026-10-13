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

import net.schmizz.concurrent.Event;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class IOUtilsTest {

    private static final long TIMEOUT_SECONDS = 5;

    @Test
    public void halfCloseOnCloseOutputStreamDelegatesBulkWrites() throws Exception {
        try (SocketPair sockets = new SocketPair()) {
            final ByteArrayOutputStream captured = new ByteArrayOutputStream();
            final AtomicInteger singleByteWrites = new AtomicInteger();
            final OutputStream spy = new OutputStream() {
                @Override
                public void write(int b) {
                    singleByteWrites.incrementAndGet();
                    captured.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) {
                    captured.write(b, off, len);
                }
            };

            final byte[] payload = new byte[32 * 1024];
            for (int i = 0; i < payload.length; i++) {
                payload[i] = (byte) i;
            }

            IOUtils.halfCloseOnCloseOutputStream(sockets.server, spy).write(payload, 0, payload.length);

            assertEquals(0, singleByteWrites.get(), "bulk write must not be decomposed into single-byte writes");
            assertArrayEquals(payload, captured.toByteArray());
        }
    }

    @Test
    public void halfCloseOnCloseOutputStreamDoesNotCloseSocketInput() throws Exception {
        try (SocketPair sockets = new SocketPair()) {
            IOUtils.halfCloseOnCloseOutputStream(sockets.server).close();

            assertFalse(sockets.server.isClosed());
            assertFalse(sockets.server.isInputShutdown());
            assertTrue(sockets.server.isOutputShutdown());
        }
    }

    @Test
    public void halfCloseOnCloseOutputStreamIsIdempotentAfterSocketClosed() throws Exception {
        try (SocketPair sockets = new SocketPair()) {
            final OutputStream out = IOUtils.halfCloseOnCloseOutputStream(sockets.server);
            sockets.server.close();

            out.close(); // must not throw even though the socket is already closed
        }
    }

    @Test
    public void streamCopierEOFOnChannelShouldHalfCloseSocketWithoutErrorOnReverseCopy() throws Exception {
        try (SocketPair sockets = new SocketPair()) {
            final LoggerFactory loggerFactory = LoggerFactory.DEFAULT;

            final Event<IOException> soc2chan = new StreamCopier(sockets.server.getInputStream(), new ByteArrayOutputStream(), loggerFactory)
                    .spawnDaemon("soc2chan");
            final Event<IOException> chan2soc = new StreamCopier(new ByteArrayInputStream(new byte[0]), IOUtils.halfCloseOnCloseOutputStream(sockets.server), loggerFactory)
                    .spawnDaemon("chan2soc");

            // Channel side is at EOF immediately: it should half-close the socket, not error.
            chan2soc.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertFalse(chan2soc.inError());

            // The reverse copy keeps running until the socket peer closes its side.
            assertTrue(sockets.server.isOutputShutdown());
            assertFalse(soc2chan.isSet());

            sockets.client.shutdownOutput();

            soc2chan.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertFalse(soc2chan.inError());
        }
    }

    @Test
    public void streamCopierEOFOnChannelClosesEntireSocketAndErrorsReverseCopy() throws Exception {
        // Characterises the pre-fix behaviour: closing the raw socket OutputStream on channel EOF
        // tears down the whole socket and makes the still-running reverse copy fail.
        try (SocketPair sockets = new SocketPair()) {
            final LoggerFactory loggerFactory = LoggerFactory.DEFAULT;

            final Event<IOException> soc2chan = new StreamCopier(sockets.server.getInputStream(), new ByteArrayOutputStream(), loggerFactory)
                    .spawnDaemon("soc2chan");
            final Event<IOException> chan2soc = new StreamCopier(new ByteArrayInputStream(new byte[0]), sockets.server.getOutputStream(), loggerFactory)
                    .spawnDaemon("chan2soc");

            chan2soc.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            assertFalse(chan2soc.inError());

            assertThrows(IOException.class, () -> soc2chan.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            assertTrue(soc2chan.inError());
            assertFalse(chan2soc.inError());
        }
    }

    /** A connected loopback socket pair, established without an accept thread. */
    private static final class SocketPair implements AutoCloseable {
        final Socket client;
        final Socket server;

        SocketPair() throws IOException {
            try (ServerSocket listener = new ServerSocket(0)) {
                listener.setSoTimeout((int) TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
                final Socket c = new Socket();
                c.connect(new InetSocketAddress("127.0.0.1", listener.getLocalPort()),
                        (int) TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
                this.client = c;
                this.server = listener.accept();
            }
        }

        @Override
        public void close() {
            IOUtils.closeQuietly(client, server);
        }
    }
}
