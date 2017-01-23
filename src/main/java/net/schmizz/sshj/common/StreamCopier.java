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
import net.schmizz.concurrent.ExceptionChainer;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class StreamCopier {

    public interface Listener {

        void reportProgress(long transferred)
                throws IOException;

    }

    private static final Listener NULL_LISTENER = new Listener() {
        @Override
        public void reportProgress(long transferred) {
        }
    };

    private final LoggerFactory loggerFactory;
    private final Logger log;
    private final InputStream in;
    private final OutputStream out;

    private Listener listener = NULL_LISTENER;

    private int bufSize = 1;
    private boolean keepFlushing = true;
    private long length = -1;

    public StreamCopier(InputStream in, OutputStream out, LoggerFactory loggerFactory) {
        this.in = in;
        this.out = out;
        this.loggerFactory = loggerFactory;
        this.log = loggerFactory.getLogger(getClass());
    }

    public StreamCopier bufSize(int bufSize) {
        this.bufSize = bufSize;
        return this;
    }

    public StreamCopier keepFlushing(boolean keepFlushing) {
        this.keepFlushing = keepFlushing;
        return this;
    }

    public StreamCopier listener(Listener listener) {
        if (listener == null) {
            this.listener = NULL_LISTENER;
        } else {
            this.listener = listener;
        }
        return this;
    }

    public StreamCopier length(long length) {
        this.length = length;
        return this;
    }

    public Event<IOException> spawn(String name) {
        return spawn(name, false);
    }

    public Event<IOException> spawnDaemon(String name) {
        return spawn(name, true);
    }

    private Event<IOException> spawn(final String name, final boolean daemon) {
        final Event<IOException> doneEvent =
                new Event<IOException>("copyDone", new ExceptionChainer<IOException>() {
                    @Override
                    public IOException chain(Throwable t) {
                        return (t instanceof IOException) ? (IOException) t : new IOException(t);
                    }
                }, loggerFactory);

        new Thread() {
            {
                setName(name);
                setDaemon(daemon);
            }

            @Override
            public void run() {
                try {
                    log.debug("Will copy from {} to {}", in, out);
                    copy();
                    log.debug("Done copying from {}", in);
                    doneEvent.set();
                } catch (IOException ioe) {
                    log.error(String.format("In pipe from %1$s to %2$s", in.toString(), out.toString()), ioe);
                    doneEvent.deliverError(ioe);
                }
            }
        }.start();
        return doneEvent;
    }

    public long copy()
            throws IOException {
        final byte[] buf = new byte[bufSize];
        long count = 0;
        int read = 0;

        final long startTime = System.currentTimeMillis();

        if (length == -1) {
            while ((read = in.read(buf)) != -1) {
                count += write(buf, count, read);
            }
        } else {
            while (count < length && (read = in.read(buf, 0, (int) Math.min(bufSize, length - count))) != -1) {
                count += write(buf, count, read);
            }
        }

        if (!keepFlushing)
            out.flush();

        final double timeSeconds = (System.currentTimeMillis() - startTime) / 1000.0;
        final double sizeKiB = count / 1024.0;
        log.debug(String.format("%1$,.1f KiB transferred in %2$,.1f seconds (%3$,.2f KiB/s)", sizeKiB, timeSeconds, (sizeKiB / timeSeconds)));

        if (length != -1 && read == -1)
            throw new IOException("Encountered EOF, could not transfer " + length + " bytes");

        return count;
    }

    private long write(byte[] buf, long curPos, int len)
            throws IOException {
        out.write(buf, 0, len);
        if (keepFlushing)
            out.flush();
        listener.reportProgress(curPos + len);
        return len;
    }

}
