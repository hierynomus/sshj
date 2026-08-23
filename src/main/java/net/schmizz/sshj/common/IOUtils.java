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
import java.io.FilterOutputStream;
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
     * ({@link Socket#shutdownOutput()}) instead of closing the entire socket.
     */
    public static OutputStream halfCloseOnCloseOutputStream(final Socket socket)
            throws IOException {
        final OutputStream out = socket.getOutputStream();
        return new FilterOutputStream(out) {
            @Override
            public void close()
                    throws IOException {
                socket.shutdownOutput();
            }
        };
    }

}
