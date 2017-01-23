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

public abstract class KeepAlive extends Thread {
    protected final Logger log;
    protected final ConnectionImpl conn;

    protected int keepAliveInterval = 0;

    protected KeepAlive(ConnectionImpl conn, String name) {
        this.conn = conn;
        log = conn.getTransport().getConfig().getLoggerFactory().getLogger(getClass());
        setName(name);
    }

    public synchronized int getKeepAliveInterval() {
        return keepAliveInterval;
    }

    public synchronized void setKeepAliveInterval(int keepAliveInterval) {
        this.keepAliveInterval = keepAliveInterval;
        if (keepAliveInterval > 0 && getState() == State.NEW) {
            start();
        }
        notify();
    }

    synchronized protected int getPositiveInterval()
            throws InterruptedException {
        while (keepAliveInterval <= 0) {
            wait();
        }
        return keepAliveInterval;
    }

    @Override
    public void run() {
        log.debug("Starting {}, sending keep-alive every {} seconds", getClass().getSimpleName(), keepAliveInterval);
        try {
            while (!isInterrupted()) {
                final int hi = getPositiveInterval();
                if (conn.getTransport().isRunning()) {
                    log.debug("Sending keep-alive since {} seconds elapsed", hi);
                    doKeepAlive();
                }
                Thread.sleep(hi * 1000);
            }
        } catch (InterruptedException e) {
            // Interrupt signal may be catched when sleeping.      
        } catch (Exception e) {
            // If we weren't interrupted, kill the transport, then this exception was unexpected.
            // Else we're in shutdown-mode already, so don't forcibly kill the transport.
            if (!isInterrupted()) {
                conn.getTransport().die(e);
            }
        }

        log.debug("Stopping {}", getClass().getSimpleName());

    }

    protected abstract void doKeepAlive() throws TransportException, ConnectionException;
}
