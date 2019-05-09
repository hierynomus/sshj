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

import net.schmizz.concurrent.Event;
import net.schmizz.sshj.common.IOUtils;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.sshj.backport.Sockets.asCloseable;

public class SocketStreamCopyMonitor
        extends Thread {

    private SocketStreamCopyMonitor(Runnable r) {
        super(r);
        setName("sockmon");
        setDaemon(true);
    }

    public static void monitor(final int frequency, final TimeUnit unit,
                               final Event<IOException> x, final Event<IOException> y,
                               final Channel channel, final Socket socket) {
        new SocketStreamCopyMonitor(new Runnable() {
            public void run() {
                try {
                    await(x);
                    await(y);
                } catch (IOException ignored) {
                } finally {
                    IOUtils.closeQuietly(channel, asCloseable(socket));
                }
            }

            private void await(final Event<IOException> event) throws IOException {
                while(true){
                    if(event.tryAwait(frequency, unit)){
                        break;
                    }
                }
            }
        }).start();
    }

}
