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
package net.schmizz.sshj.userauth.method;

import net.schmizz.sshj.common.SSHPacketHandler;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.AuthParams;
import net.schmizz.sshj.userauth.UserAuthException;

/** An authentication method of the <a href="http://www.ietf.org/rfc/rfc4252.txt">SSH Authentication Protocol</a>. */
public interface AuthMethod
        extends SSHPacketHandler {

    /** @return assigned name of this authentication method */
    String getName();

    /**
     * This method must be called before requesting authentication with this method.
     *
     * @param params parameters needed for authentication
     */
    void init(AuthParams params);

    /**
     * @throws UserAuthException  if there is an error with the request
     * @throws TransportException if there is a transport-related error
     */
    void request()
            throws UserAuthException, TransportException;

    /** @return whether authentication should be reattempted if it failed. */
    boolean shouldRetry();

}
