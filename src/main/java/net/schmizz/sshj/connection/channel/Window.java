/*
 * Copyright 2010-2012 sshj contributors
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

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.connection.ConnectionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Window {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected final Object lock = new Object();

    protected final int maxPacketSize;

    protected long size;

    public Window(long initialWinSize, int maxPacketSize) {
        size = initialWinSize;
        this.maxPacketSize = maxPacketSize;
    }

    public void expand(long inc) {
        synchronized (lock) {
            size += inc;
            log.debug("Increasing by {} up to {}", inc, size);
            lock.notifyAll();
        }
    }

    public int getMaxPacketSize() {
        return maxPacketSize;
    }

    public long getSize() {
        synchronized (lock) {
            return size;
        }
    }

    public void consume(long dec)
            throws ConnectionException {
        synchronized (lock) {
            size -= dec;
            log.debug("Consuming by {} down to {}", dec, size);
            if (size < 0)
                throw new ConnectionException("Window consumed to below 0");
        }
    }

    @Override
    public String toString() {
        return "[winSize=" + size + "]";
    }

    /** Controls how much data we can send before an adjustment notification from remote end is required. */
    public static final class Remote
            extends Window {

        public Remote(long initialWinSize, int maxPacketSize) {
            super(initialWinSize, maxPacketSize);
        }

        public long awaitExpansion(long was)
                throws ConnectionException {
            synchronized (lock) {
                while (size <= was) {
                    log.debug("Waiting, need size to grow from {} bytes", was);
                    try {
                        lock.wait();
                    } catch (InterruptedException ie) {
                        throw new ConnectionException(ie);
                    }
                }
                return size;
            }
        }

        public void consume(long howMuch) {
            try {
                super.consume(howMuch);
            } catch (ConnectionException e) { // It's a bug if we consume more than remote allowed
                throw new SSHRuntimeException(e);
            }
        }

    }

    /** Controls how much data remote end can send before an adjustment notification from us is required. */
    public static final class Local
            extends Window {

        private final long initialSize;
        private final long threshold;

        public Local(long initialWinSize, int maxPacketSize) {
            super(initialWinSize, maxPacketSize);
            this.initialSize = initialWinSize;
            threshold = Math.min(maxPacketSize * 20, initialSize / 4);
        }

        public long neededAdjustment() {
            synchronized (lock) {
                return (size <= threshold) ? (initialSize - size) : 0;
            }
        }

    }

}
