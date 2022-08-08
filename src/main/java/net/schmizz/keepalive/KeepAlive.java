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
package net.schmizz.keepalive;

import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;

import java.util.concurrent.TimeUnit;

public abstract class KeepAlive extends Thread {
    protected final Logger log;
    protected final ConnectionImpl conn;

    protected int keepAliveInterval = 0;

    protected KeepAlive(ConnectionImpl conn, String name) {
        this.conn = conn;
        log = conn.getTransport().getConfig().getLoggerFactory().getLogger(getClass());
        setName(name);
        setDaemon(true);
    }

    /**
     * KeepAlive enabled based on KeepAlive interval
     *
     * @return Enabled when KeepInterval is greater than 0
     */
    public boolean isEnabled() {
        return keepAliveInterval > 0;
    }

    /**
     * Get KeepAlive interval in seconds
     *
     * @return KeepAlive interval in seconds defaults to 0
     */
    public synchronized int getKeepAliveInterval() {
        return keepAliveInterval;
    }

    /**
     * Set KeepAlive interval in seconds
     *
     * @param keepAliveInterval KeepAlive interval in seconds
     */
    public synchronized void setKeepAliveInterval(int keepAliveInterval) {
        this.keepAliveInterval = keepAliveInterval;
    }

    @Override
    public void run() {
        log.debug("{} Started with interval [{} seconds]", getClass().getSimpleName(), keepAliveInterval);
        try {
            while (!isInterrupted()) {
                final int interval = getKeepAliveInterval();
                if (conn.getTransport().isRunning()) {
                    log.debug("{} Sending after interval [{} seconds]", getClass().getSimpleName(), interval);
                    doKeepAlive();
                }
                TimeUnit.SECONDS.sleep(interval);
            }
        } catch (InterruptedException e) {
            // this is almost certainly a planned interruption, but even so, no harm in setting the interrupt flag
            Thread.currentThread().interrupt();
            log.trace("{} Interrupted while sleeping", getClass().getSimpleName());
        } catch (Exception e) {
            // If we weren't interrupted, kill the transport, then this exception was unexpected.
            // Else we're in shutdown-mode already, so don't forcibly kill the transport.
            if (!isInterrupted()) {
                conn.getTransport().die(e);
            }
        }
        log.debug("{} Stopped", getClass().getSimpleName());
    }

    protected abstract void doKeepAlive() throws TransportException, ConnectionException;
}
