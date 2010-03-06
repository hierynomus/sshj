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
package net.schmizz.concurrent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Represents future data of the parameterized type {@code V} and allows waiting on it. An exception may also be
 * delivered to a waiter, and will be of the parameterized type {@code T}.
 * <p/>
 * For atomic operations on a future, e.g. checking if a value is set and if it is not then setting it - in other words,
 * Compare-And-Set type operations - the associated lock for the future should be acquired while doing so.
 */
public class Future<V, T extends Throwable> {

    private final Logger log;

    private final ExceptionChainer<T> chainer;
    private final ReentrantLock lock;
    private final Condition cond;

    private V val;
    private T pendingEx;

    /**
     * Creates this future with given {@code name} and exception {@code chainer}. Allocates a new {@link
     * java.util.concurrent.locks.Lock lock} object for this future.
     *
     * @param name    name of this future
     * @param chainer {@link ExceptionChainer} that will be used for chaining exceptions
     */
    public Future(String name, ExceptionChainer<T> chainer) {
        this(name, chainer, null);
    }

    /**
     * Creates this future with given {@code name}, exception {@code chainer}, and associated {@code lock}.
     *
     * @param name    name of this future
     * @param chainer {@link ExceptionChainer} that will be used for chaining exceptions
     * @param lock    lock to use
     */
    public Future(String name, ExceptionChainer<T> chainer, ReentrantLock lock) {
        this.log = LoggerFactory.getLogger("<< " + name + " >>");
        this.chainer = chainer;
        this.lock = lock == null ? new ReentrantLock() : lock;
        this.cond = this.lock.newCondition();
    }

    /**
     * Set this future's value to {@code val}. Any waiters will be delivered this value.
     *
     * @param val the value
     */
    public void set(V val) {
        lock();
        try {
            log.debug("Setting to `{}`", val);
            this.val = val;
            cond.signalAll();
        } finally {
            unlock();
        }
    }

    /**
     * Queues error that will be thrown in any waiting thread or any thread that attempts to wait on this future
     * hereafter.
     *
     * @param e the error
     */
    public void error(Throwable e) {
        lock();
        try {
            pendingEx = chainer.chain(e);
            cond.signalAll();
        } finally {
            unlock();
        }
    }

    /** Clears this future by setting its value and queued exception to {@code null}. */
    public void clear() {
        lock();
        try {
            pendingEx = null;
            set(null);
        } finally {
            unlock();
        }
    }

    /**
     * Wait indefinitely for this future's value to be set.
     *
     * @return the value
     *
     * @throws T in case another thread informs the future of an error meanwhile
     */
    public V get()
            throws T {
        return get(0, TimeUnit.SECONDS);
    }

    /**
     * Wait for {@code timeout} seconds for this future's value to be set.
     *
     * @param timeout the timeout in seconds
     * @param unit    time unit
     *
     * @return the value
     *
     * @throws T in case another thread informs the future of an error meanwhile, or the timeout expires
     */
    public V get(long timeout, TimeUnit unit)
            throws T {
        lock();
        try {
            if (pendingEx != null)
                throw pendingEx;
            if (val != null)
                return val;
            log.debug("Awaiting");
            while (val == null && pendingEx == null)
                if (timeout == 0)
                    cond.await();
                else if (!cond.await(timeout, unit))
                    throw chainer.chain(new TimeoutException("Timeout expired"));
            if (pendingEx != null) {
                log.error("Woke to: {}", pendingEx.toString());
                throw pendingEx;
            }
            return val;
        } catch (InterruptedException ie) {
            throw chainer.chain(ie);
        } finally {
            unlock();
        }
    }

    /** @return whether this future has a value set, and no error waiting to pop. */
    public boolean isSet() {
        lock();
        try {
            return pendingEx == null && val != null;
        } finally {
            unlock();
        }
    }

    /** @return whether this future currently has an error set. */
    public boolean hasError() {
        lock();
        try {
            return pendingEx != null;
        } finally {
            unlock();
        }
    }

    /** @return whether this future has threads waiting on it. */
    public boolean hasWaiters() {
        lock();
        try {
            return lock.hasWaiters(cond);
        } finally {
            unlock();
        }
    }

    /**
     * Lock using the associated lock. Use as part of a {@code try-finally} construct in conjunction with {@link
     * #unlock()}.
     */
    public void lock() {
        lock.lock();
    }

    /**
     * Unlock using the associated lock. Use as part of a {@code try-finally} construct in conjunction with {@link
     * #lock()}.
     */
    public void unlock() {
        lock.unlock();
    }

}
