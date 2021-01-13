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

import java.util.Objects;

public class Parameters {

    private final String localHost;
    private final int localPort;
    private final String remoteHost;
    private final int remotePort;

    public Parameters(String localHost, int localPort, String remoteHost, int remotePort) {
        this.localHost = localHost;
        this.localPort = localPort;
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public int getRemotePort() {
        return remotePort;
    }

    public String getLocalHost() {
        return localHost;
    }

    public int getLocalPort() {
        return localPort;
    }

    @Override
    public int hashCode() {
        return Objects.hash(localHost, localPort, remoteHost, remotePort);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) { return true; }
        if (!(obj instanceof Parameters)) { return false; }
        Parameters other = (Parameters) obj;
        return Objects.equals(localHost,  other.localHost)  && localPort  == other.localPort &&
               Objects.equals(remoteHost, other.remoteHost) && remotePort == other.remotePort;
    }

    @Override
    public String toString() {
        return "Parameters [localHost="  + localHost  + ", localPort="  + localPort  + ", "+
                           "remoteHost=" + remoteHost + ", remotePort=" + remotePort + "]";
    }

}
