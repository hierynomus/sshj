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

import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.TransportException;

import java.util.LinkedList;
import java.util.Queue;

import static java.lang.String.format;
import static net.schmizz.sshj.common.DisconnectReason.CONNECTION_LOST;

public class KeepAliveRunner extends KeepAlive {

    /** The max number of keep-alives that should be unanswered before killing the connection. */
    private int maxAliveCount = 5;

    /** The queue of promises. */
    private final Queue<Promise<SSHPacket, ConnectionException>> queue =
            new LinkedList<Promise<SSHPacket, ConnectionException>>();

    KeepAliveRunner(ConnectionImpl conn) {
        super(conn, "keep-alive");
    }

    synchronized public int getMaxAliveCount() {
        return maxAliveCount;
    }

    synchronized public void setMaxAliveCount(int maxAliveCount) {
        this.maxAliveCount = maxAliveCount;
    }

    @Override
    protected void doKeepAlive() throws TransportException, ConnectionException {
        // Ensure the service is set... This means that the key exchange is done and the connection is up.
        if (conn.equals(conn.getTransport().getService())) {
            emptyQueue(queue);
            checkMaxReached(queue);
            queue.add(conn.sendGlobalRequest("keepalive@openssh.com", true, new byte[0]));
        }
    }

    private void checkMaxReached(Queue<Promise<SSHPacket, ConnectionException>> queue) throws ConnectionException {
        if (queue.size() >= maxAliveCount) {
            throw new ConnectionException(CONNECTION_LOST,
                    format("Did not receive any keep-alive response for %s seconds", maxAliveCount * keepAliveInterval));
        }
    }

    private void emptyQueue(Queue<Promise<SSHPacket, ConnectionException>> queue) {
        Promise<SSHPacket, ConnectionException> peek = queue.peek();
        while (peek != null && peek.isFulfilled()) {
            log.debug("Received response from server to our keep-alive.");
            queue.remove();
            peek = queue.peek();
        }
    }
}
