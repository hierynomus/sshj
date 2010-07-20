/*
 * Copyright 2010 Shikhar Bhushan
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class StreamCopier
        extends Thread {

    private static final Logger LOG = LoggerFactory.getLogger(StreamCopier.class);

    public interface ErrorCallback {
        void onError(IOException ioe);
    }

    public static ErrorCallback closeOnErrorCallback(final Closeable... toClose) {
        return new ErrorCallback() {
            @Override
            public void onError(IOException ioe) {
                IOUtils.closeQuietly(toClose);
            }
        };
    }

    public interface Listener {
        void reportProgress(long transferred);
    }

    public static long copy(InputStream in, OutputStream out, int bufSize, boolean keepFlushing, Listener listener)
            throws IOException {
        long count = 0;

        final boolean reportProgress = listener != null;
        final long startTime = System.currentTimeMillis();

        final byte[] buf = new byte[bufSize];
        int read;
        while ((read = in.read(buf)) != -1) {
            out.write(buf, 0, read);
            count += read;
            if (keepFlushing)
                out.flush();
            if (reportProgress)
                listener.reportProgress(count);
        }
        if (!keepFlushing)
            out.flush();

        final double sizeKiB = count / 1024.0;
        final double timeSeconds = (System.currentTimeMillis() - startTime) / 1000.0;
        LOG.info(sizeKiB + " KiB transferred  in {} seconds ({} KiB/s)", timeSeconds, (sizeKiB / timeSeconds));

        return count;
    }

    public static long copy(InputStream in, OutputStream out, int bufSize, boolean keepFlushing)
            throws IOException {
        return copy(in, out, bufSize, keepFlushing, null);
    }

    public static String copyStreamToString(InputStream stream)
            throws IOException {
        final StringBuilder sb = new StringBuilder();
        int read;
        while ((read = stream.read()) != -1)
            sb.append((char) read);
        return sb.toString();
    }

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final InputStream in;
    private final OutputStream out;

    private int bufSize = 1;
    private boolean keepFlushing = true;

    private ErrorCallback errCB = new ErrorCallback() {
        @Override
        public void onError(IOException ioe) {
        }
    }; // Default null cb

    public StreamCopier(String name, InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
        setName(name);
    }

    public StreamCopier bufSize(int size) {
        bufSize = size;
        return this;
    }

    public StreamCopier keepFlushing(boolean choice) {
        keepFlushing = choice;
        return this;
    }

    public StreamCopier daemon(boolean choice) {
        setDaemon(choice);
        return this;
    }

    public StreamCopier errorCallback(ErrorCallback errCB) {
        this.errCB = errCB;
        return this;
    }

    @Override
    public void run() {
        try {
            log.debug("Wil pipe from {} to {}", in, out);
            copy(in, out, bufSize, keepFlushing);
            log.debug("EOF on {}", in);
        } catch (IOException ioe) {
            log.error("In pipe from {} to {}: " + ioe.toString(), in, out);
            errCB.onError(ioe);
        }
    }

}