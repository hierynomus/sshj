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
package net.schmizz.concurrent;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * An event can be set, cleared, or awaited, similar to Python's {@code threading.event}. The key difference is that a
 * waiter may be delivered an exception of parameterized type {@code T}.
 * <p/>
 * Uses {@link Promise} under the hood.
 */
public class Event<T extends Throwable> {

    private static final Object SOME = new Object() {
        @Override
        public String toString() {
            return "SOME";
        }
    };

    private final Promise<Object, T> promise;

    /**
     * Creates this event with given {@code name} and exception {@code chainer}. Allocates a new {@link
     * java.util.concurrent.locks.Lock Lock} object for this event.
     *
     * @param name    name of this event
     * @param chainer {@link ExceptionChainer} that will be used for chaining exceptions
     */
    public Event(String name, ExceptionChainer<T> chainer) {
        promise = new Promise<Object, T>(name, chainer);
    }

    /**
     * Creates this event with given {@code name}, exception {@code chainer}, and associated {@code lock}.
     *
     * @param name    name of this event
     * @param chainer {@link ExceptionChainer} that will be used for chaining exceptions
     * @param lock    lock to use
     */
    public Event(String name, ExceptionChainer<T> chainer, ReentrantLock lock) {
        promise = new Promise<Object, T>(name, chainer, lock);
    }

    /** Sets this event to be {@code true}. Short for {@code set(true)}. */
    public void set() {
        promise.deliver(SOME);
    }

    /** Clear this event. A cleared event {@code !isSet()}. */
    public void clear() {
        promise.clear();
    }

    /** Deliver the error {@code t} (after chaining) to any present or future waiters. */
    public void deliverError(Throwable t) {
        promise.deliverError(t);
    }

    /**
     * @return whether this event is in a 'set' state. An event is set by a call to {@link #set} or {@link
     *         #deliverError}
     */
    public boolean isSet() {
        return promise.isDelivered();
    }

    /**
     * Await this event to have a definite {@code true} or {@code false} value.
     *
     * @throws T if another thread meanwhile informs this event of an error
     */
    public void await()
            throws T {
        promise.retrieve();
    }

    /**
     * Await this event to have a definite {@code true} or {@code false} value, for {@code timeout} duration.
     *
     * @param timeout timeout
     * @param unit    the time unit for the timeout
     *
     * @throws T if another thread meanwhile informs this event of an error, or timeout expires
     */
    public void await(long timeout, TimeUnit unit)
            throws T {
        promise.retrieve(timeout, unit);
    }

    /**
     * Await this event to have a definite {@code true} or {@code false} value, for {@code timeout} duration.
     * <p/>
     * If the definite value is not available when the timeout expires, returns {@code false}.
     *
     * @param timeout timeout
     * @param unit    the time unit for the timeout
     *
     * @throws T if another thread meanwhile informs this event of an error
     */
    public boolean tryAwait(long timeout, TimeUnit unit)
            throws T {
        return promise.tryRetrieve(timeout, unit) != null;
    }

    /** @return whether there are any threads waiting on this event to be set. */
    public boolean hasWaiters() {
        return promise.hasWaiters();
    }

    /** @return whether this event is in an error state i.e. has been delivered an error. */
    public boolean inError() {
        return promise.inError();
    }

    /** Acquire the lock associated with this event. */
    public void lock() {
        promise.lock();
    }

    /** Release the lock associated with this event. */
    public void unlock() {
        promise.unlock();
    }

    @Override
    public String toString() {
        return promise.toString();
    }

}