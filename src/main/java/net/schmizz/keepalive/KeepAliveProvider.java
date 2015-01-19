package net.schmizz.keepalive;

import net.schmizz.sshj.connection.ConnectionImpl;

public abstract class KeepAliveProvider {

    public static final KeepAliveProvider HEARTBEAT = new KeepAliveProvider() {
        @Override
        public KeepAlive provide(ConnectionImpl connection) {
            return new Heartbeater(connection);
        }
    };

    public static final KeepAliveProvider KEEP_ALIVE = new KeepAliveProvider() {
        @Override
        public KeepAlive provide(ConnectionImpl connection) {
            return new KeepAliveRunner(connection);
        }
    };

    public abstract KeepAlive provide(ConnectionImpl connection);


}
