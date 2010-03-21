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
package net.schmizz.sshj.connection.channel;

import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.connection.ConnectionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Window {

    protected final Logger log;

    protected final Object lock = new Object();

    protected final int maxPacketSize;

    protected int size;

    public Window(int chanID, String kindOfWindow, int initialWinSize, int maxPacketSize) {
        log = LoggerFactory.getLogger("<< chan#" + chanID + " / " + kindOfWindow + " >>");
        size = initialWinSize;
        this.maxPacketSize = maxPacketSize;
    }

    public void expand(int inc) {
        synchronized (lock) {
            log.debug("Increasing by {} up to {}", inc, size);
            size += inc;
            lock.notifyAll();
        }
    }

    public int getMaxPacketSize() {
        return maxPacketSize;
    }

    public int getSize() {
        return size;
    }

    public void consume(int dec) {
        synchronized (lock) {
            log.debug("Consuming by " + dec + " down to " + size);
            size -= dec;
            if (size < 0)
                throw new SSHRuntimeException("Window consumed to below 0");
        }
    }

    @Override
    public String toString() {
        return "[winSize=" + size + "]";
    }

    /** Controls how much data we can send before an adjustment notification from remote end is required. */
    public static final class Remote
            extends Window {

        public Remote(int chanID, int initialWinSize, int maxPacketSize) {
            super(chanID, "remote win", initialWinSize, maxPacketSize);
        }

        public void waitAndConsume(int howMuch)
                throws ConnectionException {
            synchronized (lock) {
                while (size < howMuch) {
                    log.debug("Waiting, need window space for {} bytes", howMuch);
                    try {
                        lock.wait();
                    } catch (InterruptedException ie) {
                        throw new ConnectionException(ie);
                    }
                }
                consume(howMuch);
            }
        }

    }

    /** Controls how much data remote end can send before an adjustment notification from us is required. */
    public static final class Local
            extends Window {

        private final int initialSize;
        private final int threshold;

        public Local(int chanID, int initialWinSize, int maxPacketSize) {
            super(chanID, "local win", initialWinSize, maxPacketSize);
            this.initialSize = initialWinSize;
            threshold = Math.min(maxPacketSize * 20, initialSize / 4);
        }

        public int neededAdjustment() {
            synchronized (lock) {
                return (size - threshold <= 0) ? (initialSize - size) : 0;
            }
        }

    }

}
