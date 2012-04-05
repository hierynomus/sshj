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
package net.schmizz.sshj;

import net.schmizz.sshj.common.ErrorNotifiable;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacketHandler;
import net.schmizz.sshj.transport.TransportException;

/** Represents a service running on top of the SSH transport layer. */
public interface Service
        extends SSHPacketHandler, ErrorNotifiable {

    /** @return the assigned name for this SSH service. */
    String getName();

    /**
     * Notifies this service that a {@code SSH_MSG_UNIMPLEMENTED} was received for packet with given sequence number.
     * Meant to be invoked as a callback by the transport layer.
     *
     * @param seqNum sequence number of the packet which the server claims is unimplemented
     *
     * @throws SSHException if the packet is unexpected and may represent a disruption
     */
    void notifyUnimplemented(long seqNum)
            throws SSHException;

    /**
     * Request and install this service with the associated transport. Implementations should aim to make this method
     * idempotent by first checking the {@link net.schmizz.sshj.transport.Transport#getService()}  currently active
     * service}.
     *
     * @throws TransportException if there is an error sending the service request
     */
    void request()
            throws TransportException;

}