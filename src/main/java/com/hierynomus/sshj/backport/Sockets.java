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
package com.hierynomus.sshj.backport;

import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;

public class Sockets {

    /**
     * Java 7 and up have Socket implemented as Closeable, whereas Java6 did not have this inheritance.
     * @param socket The socket to wrap as Closeable
     * @return The (potentially wrapped) Socket as a Closeable.
     */
    public static Closeable asCloseable(final Socket socket) {
        if (Closeable.class.isAssignableFrom(socket.getClass())) {
            return Closeable.class.cast(socket);
        } else {
            return new Closeable() {
                @Override
                public void close() throws IOException {
                    socket.close();
                }
            };
        }
    }
}
