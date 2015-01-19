package net.schmizz.keepalive;

import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class KeepAlive extends Thread {
    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected final ConnectionImpl conn;

    protected int keepAliveInterval = 0;

    protected KeepAlive(ConnectionImpl conn, String name) {
        this.conn = conn;
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
