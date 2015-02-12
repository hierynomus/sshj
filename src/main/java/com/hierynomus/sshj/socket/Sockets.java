package com.hierynomus.sshj.socket;

import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;

public class Sockets {

    /**
     * Java 7 and up have Socket implemented as Closeable, whereas Java6 did not have this inheritance.
     * @param socket The socket to wrap as Closeable
     * @return
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
