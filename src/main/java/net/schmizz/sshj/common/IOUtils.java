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

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class IOUtils {

    public static void closeQuietly(Closeable... closeables) {
        closeQuietly(LoggerFactory.DEFAULT, closeables);
    }

    public static ByteArrayOutputStream readFully(InputStream stream)
            throws IOException {
        return readFully(stream, LoggerFactory.DEFAULT);
    }

    public static void closeQuietly(LoggerFactory loggerFactory, Closeable... closeables) {
        for (Closeable c : closeables) {
            try {
                if (c != null)
                    c.close();
            } catch (IOException logged) {
                loggerFactory.getLogger(IOUtils.class).warn("Error closing {} - {}", c, logged);
            }
        }
    }

    public static ByteArrayOutputStream readFully(InputStream stream, LoggerFactory loggerFactory)
            throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new StreamCopier(stream, baos, loggerFactory).copy();
        return baos;
    }

    /**
     * Wraps a socket output stream so that {@link OutputStream#close()} performs a TCP half-close
     * ({@link Socket#shutdownOutput()}) instead of closing the entire socket. All write and flush
     * calls are delegated to the underlying stream as-is (in particular bulk writes are not
     * decomposed into single-byte writes).
     */
    public static OutputStream halfCloseOnCloseOutputStream(final Socket socket)
            throws IOException {
        return halfCloseOnCloseOutputStream(socket, socket.getOutputStream());
    }

    static OutputStream halfCloseOnCloseOutputStream(final Socket socket, final OutputStream out) {
        return new OutputStream() {
            @Override
            public void write(int b)
                    throws IOException {
                out.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len)
                    throws IOException {
                out.write(b, off, len);
            }

            @Override
            public void flush()
                    throws IOException {
                out.flush();
            }

            @Override
            public void close()
                    throws IOException {
                if (!socket.isClosed() && !socket.isOutputShutdown()) {
                    socket.shutdownOutput();
                }
            }
        };
    }

}
