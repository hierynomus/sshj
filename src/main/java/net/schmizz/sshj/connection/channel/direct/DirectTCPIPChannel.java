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

public class DirectTCPIPChannel extends AbstractDirectChannel {
    protected final Parameters parameters;

    protected DirectTCPIPChannel(Connection conn, Parameters parameters) {
        super(conn, "direct-tcpip");
        this.parameters = parameters;
    }

    @Override
    protected SSHPacket buildOpenReq() {
        return super.buildOpenReq()
                .putString(parameters.getRemoteHost())
                .putUInt32(parameters.getRemotePort())
                .putString(parameters.getLocalHost())
                .putUInt32(parameters.getLocalPort());
    }
}
