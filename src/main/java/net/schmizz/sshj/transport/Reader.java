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
package net.schmizz.sshj.transport;

import org.slf4j.Logger;

import java.io.InputStream;
import java.net.SocketTimeoutException;

public final class Reader
        extends Thread {

    private final Logger log;
    private final TransportImpl trans;

    public Reader(TransportImpl trans) {
        this.trans = trans;
        log = trans.getConfig().getLoggerFactory().getLogger(getClass());
        setName("reader");
    }

    @Override
    public void run() {
        try {

            final Decoder decoder = trans.getDecoder();
            final InputStream inp = trans.getConnInfo().in;

            final byte[] recvbuf = new byte[decoder.getMaxPacketLength()];

            int needed = 1;

            while (!isInterrupted()) {
                int read;
                try {
                    read = inp.read(recvbuf, 0, needed);
                } catch(SocketTimeoutException e) {
                    if (isInterrupted()) {
                        throw e;
                    }
                    continue;
                }
                if (read == -1) {
                    throw new TransportException("Broken transport; encountered EOF");
                } else {
                    needed = decoder.received(recvbuf, read);
                }
            }
        } catch (Exception e) {
            // We are meant to shut up and draw to a close if interrupted
            if (!isInterrupted()) {
                trans.die(e);
            }
        }

        log.debug("Stopping");
    }

}
