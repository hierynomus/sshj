package net.schmizz.keepalive;

import net.schmizz.sshj.Config;
import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * This implementation manages all {@link KeepAlive}s using configured number of threads. It works like a
 * thread pool, thus {@link BoundedKeepAliveProvider#shutdown()} must be called to clean up resources.
 * <br>
 * This provider uses {@link KeepAliveRunner#doKeepAlive()} as delegate, so it supports maxKeepAliveCount
 * parameter. All instances provided by this provider have identical configuration.
 */
public class BoundedKeepAliveProvider extends KeepAliveProvider {

    public int maxKeepAliveCount = 3;
    public int keepAliveInterval = 5;

    protected final KeepAliveMonitor monitor;


    public BoundedKeepAliveProvider(LoggerFactory loggerFactory, int numberOfThreads) {
        this.monitor = new KeepAliveMonitor(loggerFactory, numberOfThreads);
    }

    public void setKeepAliveInterval(int interval) {
        keepAliveInterval = interval;
    }

    public void setMaxKeepAliveCount(int count) {
        maxKeepAliveCount = count;
    }

    @Override
    public KeepAlive provide(ConnectionImpl connection) {
        return new Impl(connection, "bounded-keepalive-impl");
    }

    public void shutdown() throws InterruptedException {
        monitor.shutdown();
    }

    class Impl extends KeepAlive {

        private final KeepAliveRunner delegate;

        protected Impl(ConnectionImpl conn, String name) {
            super(conn, name);
            this.delegate = new KeepAliveRunner(conn);

            // take care here, some parameters are set to both delegate and this
            this.delegate.setMaxAliveCount(BoundedKeepAliveProvider.this.maxKeepAliveCount);
            super.keepAliveInterval = BoundedKeepAliveProvider.this.keepAliveInterval;
        }

        @Override
        protected void doKeepAlive() throws TransportException, ConnectionException {
            delegate.doKeepAlive();
        }

        @Override
        public void startKeepAlive() {
            monitor.register(this);
        }

    }

    protected static class KeepAliveMonitor {
        private final Logger logger;

        private final PriorityBlockingQueue<Wrapper> q =
                new PriorityBlockingQueue<>(32, Comparator.comparingLong(w -> w.nextTimeMillis));
        private static final List<Thread> workerThreads = new ArrayList<>();

        private volatile long idleSleepMillis = 100;
        private final int numberOfThreads;

        volatile boolean started = false;

        private final ReentrantLock lock = new ReentrantLock();
        private final Condition shutDown = lock.newCondition();
        private final AtomicInteger shutDownCnt = new AtomicInteger(0);

        public KeepAliveMonitor(LoggerFactory loggerFactory, int numberOfThreads) {
            this.numberOfThreads = numberOfThreads;
            logger = loggerFactory.getLogger(KeepAliveMonitor.class);
        }

        // made public for test
        public void register(KeepAlive keepAlive) {
            if (!started) {
                start();
            }
            q.add(new Wrapper(keepAlive));
        }

        public void setIdleSleepMillis(long idleSleepMillis) {
            this.idleSleepMillis = idleSleepMillis;
        }

        private void sleep() {
            sleep(idleSleepMillis);
        }

        private void sleep(long millis) {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        private synchronized void start() {
            if (started) {
                return;
            }

            for (int i = 0; i < numberOfThreads; i++) {
                Thread t = new Thread(this::doStart);
                workerThreads.add(t);
            }
            workerThreads.forEach(Thread::start);
            started = true;
        }


        private void doStart() {
            while (!Thread.currentThread().isInterrupted()) {
                Wrapper wrapper;

                if (q.isEmpty() || (wrapper = q.poll()) == null) {
                    sleep();
                    continue;
                }

                long currentTimeMillis = System.currentTimeMillis();
                if (wrapper.nextTimeMillis > currentTimeMillis) {
                    long sleepMillis = wrapper.nextTimeMillis - currentTimeMillis;
                    logger.debug("{} millis until next check, sleep", sleepMillis);
                    sleep(sleepMillis);
                }

                try {
                    wrapper.keepAlive.doKeepAlive();
                    q.add(wrapper.reschedule());
                } catch (Exception e) {
                    // If we weren't interrupted, kill the transport, then this exception was unexpected.
                    // Else we're in shutdown-mode already, so don't forcibly kill the transport.
                    if (!Thread.currentThread().isInterrupted()) {
                        wrapper.keepAlive.conn.getTransport().die(e);
                    }
                }
            }
            lock.lock();
            try {
                if (shutDownCnt.incrementAndGet() == numberOfThreads) {
                    shutDown.signal();
                }
            } finally {
                lock.unlock();
            }
        }

        private synchronized void shutdown() throws InterruptedException {
            if (workerThreads.isEmpty()) {
                return;
            }
            for (Thread t : workerThreads) {
                t.interrupt();
            }
            lock.lock();
            logger.info("waiting for all {} threads to finish", numberOfThreads);
            shutDown.await();
        }

        private static class Wrapper {
            private final KeepAlive keepAlive;
            private final long nextTimeMillis;

            private Wrapper(KeepAlive keepAlive) {
                this.keepAlive = keepAlive;
                this.nextTimeMillis = System.currentTimeMillis() + keepAlive.keepAliveInterval * 1000L;
            }

            private Wrapper reschedule() {
                return new Wrapper(keepAlive);
            }
        }
    }
}
