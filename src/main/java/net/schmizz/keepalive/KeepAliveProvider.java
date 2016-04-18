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
