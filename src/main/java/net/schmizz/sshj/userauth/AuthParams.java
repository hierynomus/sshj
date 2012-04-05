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

package net.schmizz.sshj.userauth;

import net.schmizz.sshj.transport.Transport;

/** The parameters available to authentication methods. */
public interface AuthParams {

    /** @return name of the next service being requested */
    String getNextServiceName();

    /**
     * @return the transport which will allow sending packets; retrieving information like the session-id, remote
     *         host/port etc. which is needed by some method.
     */
    Transport getTransport();

    /** @return all userauth requests need to include the username */
    String getUsername();

}