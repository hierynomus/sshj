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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
 */

package net.schmizz.sshj.transport;

import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class Heartbeater extends Thread {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final TransportProtocol trans;

    private int interval;

    private boolean started;

    Heartbeater(TransportProtocol trans) {
        this.trans = trans;
        setName("heartbeater");
    }

    synchronized void setInterval(int interval) {
        this.interval = interval;
        if (interval != 0) {
            if (!started)
                start();
            notify();
        }
    }

    synchronized int getInterval() {
        return interval;
    }

    @Override
    public void run() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                int hi;
                synchronized (this) {
                    while ((hi = interval) == 0)
                        wait();
                }
                if (!started)
                    started = true;
                else if (trans.isRunning()) {
                    log.info("Sending heartbeat since {} seconds elapsed", hi);
                    trans.write(new SSHPacket(Message.IGNORE));
                }
                Thread.sleep(hi * 1000);
            }
        } catch (Exception e) {
            if (Thread.currentThread().isInterrupted()) {
                // We are meant to shut up and draw to a close if interrupted
            } else
                trans.die(e);
        }

        log.debug("Stopping");
    }
}
