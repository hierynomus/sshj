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
package net.schmizz.sshj.connection.channel.direct;

import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.connection.Connection;

/** A channel for creating a direct TCP/IP connection from the server to a remote address. */
public class DirectConnection extends AbstractDirectChannel {
    private final String remoteHost;
    private final int remotePort;

    public DirectConnection(Connection conn, String remoteHost, int remotePort) {
        super(conn, "direct-tcpip");
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
    }

    @Override protected SSHPacket buildOpenReq() {
        return super.buildOpenReq()
                .putString(getRemoteHost())
                .putUInt32(getRemotePort())
                .putString("localhost")
                .putUInt32(65536); // it looks like OpenSSH uses this value in stdio-forward
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public int getRemotePort() {
        return remotePort;
    }
}