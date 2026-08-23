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
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class IOUtilsTest {

    @Test
    public void halfCloseOnCloseOutputStreamDoesNotCloseSocketInput() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            final int port = serverSocket.getLocalPort();
            final Socket[] accepted = new Socket[1];
            Thread acceptThread = new Thread(() -> {
                try {
                    accepted[0] = serverSocket.accept();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            acceptThread.start();

            try (Socket clientSide = new Socket("127.0.0.1", port)) {
                acceptThread.join(5_000);

                IOUtils.halfCloseOnCloseOutputStream(accepted[0]).close();

                assertFalse(accepted[0].isClosed());
                assertFalse(accepted[0].isInputShutdown());
                assertTrue(accepted[0].isOutputShutdown());
            }
        }
    }

    @Test
    public void streamCopierEOFOnChannelShouldHalfCloseSocketWithoutErrorOnReverseCopy() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            final int port = serverSocket.getLocalPort();
            final Socket[] accepted = new Socket[1];
            Thread acceptThread = new Thread(() -> {
                try {
                    accepted[0] = serverSocket.accept();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            acceptThread.start();

            try (Socket clientSide = new Socket("127.0.0.1", port)) {
                acceptThread.join(5_000);
                final Socket socket = accepted[0];

                LoggerFactory loggerFactory = LoggerFactory.DEFAULT;

                final Event<IOException> soc2chan = new StreamCopier(socket.getInputStream(), new ByteArrayOutputStream(), loggerFactory)
                        .spawnDaemon("soc2chan");

                final Event<IOException> chan2soc = new StreamCopier(new ByteArrayInputStream(new byte[0]), IOUtils.halfCloseOnCloseOutputStream(socket), loggerFactory)
                        .spawnDaemon("chan2soc");

                chan2soc.await(5, TimeUnit.SECONDS);
                assertFalse(chan2soc.inError());

                clientSide.shutdownOutput();
                soc2chan.await(5, TimeUnit.SECONDS);

                assertFalse(soc2chan.inError());
            }
        }
    }

    @Test
    public void streamCopierEOFOnChannelClosesEntireSocketAndErrorsReverseCopy() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            final int port = serverSocket.getLocalPort();
            final Socket[] accepted = new Socket[1];
            Thread acceptThread = new Thread(() -> {
                try {
                    accepted[0] = serverSocket.accept();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            acceptThread.start();

            try (Socket clientSide = new Socket("127.0.0.1", port)) {
                acceptThread.join(5_000);
                final Socket socket = accepted[0];

                LoggerFactory loggerFactory = LoggerFactory.DEFAULT;

                final Event<IOException> soc2chan = new StreamCopier(socket.getInputStream(), new ByteArrayOutputStream(), loggerFactory)
                        .spawnDaemon("soc2chan");

                final Event<IOException> chan2soc = new StreamCopier(new ByteArrayInputStream(new byte[0]), socket.getOutputStream(), loggerFactory)
                        .spawnDaemon("chan2soc");

                chan2soc.tryAwait(5, TimeUnit.SECONDS);
                assertFalse(chan2soc.inError());

                Thread.sleep(200);
                assertTrue(soc2chan.inError());
                assertFalse(chan2soc.inError());
            }
        }
    }
}
