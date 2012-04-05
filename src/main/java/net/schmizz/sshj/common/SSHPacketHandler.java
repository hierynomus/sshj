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
package net.schmizz.sshj.common;

/**
 * An interface for classes to which packet handling may be delegated. Chains of such delegations may be used, e.g.
 * {@code packet decoder -> (SSHPacketHandler) transport layer -> (SSHPacketHandler) connection layer ->
 * (SSHPacketHandler) channel}.
 */
public interface SSHPacketHandler {

    /**
     * Delegate handling of some SSH packet to this object.
     *
     * @param msg the SSH {@link Message message identifier}
     * @param buf {@link SSHPacket} containing rest of the request
     *
     * @throws SSHException if there is a non-recoverable error
     */
    void handle(Message msg, SSHPacket buf)
            throws SSHException;

}
