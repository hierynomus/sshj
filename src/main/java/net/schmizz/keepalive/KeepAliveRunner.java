package net.schmizz.keepalive;

import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.ConnectionException;
import net.schmizz.sshj.connection.ConnectionImpl;
import net.schmizz.sshj.transport.TransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
        emptyQueue(queue);
        checkMaxReached(queue);
        queue.add(conn.sendGlobalRequest("keepalive@openssh.com", true, new byte[0]));
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
