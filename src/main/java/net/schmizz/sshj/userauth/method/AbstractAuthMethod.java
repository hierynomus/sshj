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

import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.AuthParams;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.password.AccountResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** This abstract class for {@link AuthMethod} implements common or default functionality. */
public abstract class AbstractAuthMethod
        implements AuthMethod {

    /** Logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final String name;

    /** {@link AuthParams} useful for building request. */
    protected AuthParams params;

    /** @param name the {@code name} of this authentication method. */
    protected AbstractAuthMethod(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void handle(Message msg, SSHPacket buf)
            throws UserAuthException, TransportException {
        throw new UserAuthException("Unknown packet received during " + getName() + " auth: " + msg);
    }

    @Override
    public void init(AuthParams params) {
        this.params = params;
    }

    @Override
    public void request()
            throws UserAuthException, TransportException {
        params.getTransport().write(buildReq());
    }

    @Override
    public boolean shouldRetry() {
        return false;
    }

    /**
     * Builds a {@link SSHPacket} containing the fields common to all authentication method. Method-specific fields can
     * further be put into this buffer.
     */
    protected SSHPacket buildReq()
            throws UserAuthException {
        return new SSHPacket(Message.USERAUTH_REQUEST) // SSH_MSG_USERAUTH_REQUEST
                .putString(params.getUsername()) // username goes first
                .putString(params.getNextServiceName()) // the service that we'd like on success
                .putString(name); // name of auth method
    }

    protected AccountResource makeAccountResource() {
        return new AccountResource(params.getUsername(), params.getTransport().getRemoteHost());
    }

}
