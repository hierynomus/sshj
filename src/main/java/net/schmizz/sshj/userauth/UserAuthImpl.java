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

import net.schmizz.concurrent.Promise;
import net.schmizz.sshj.AbstractService;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.method.AuthMethod;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** {@link UserAuth} implementation. */
public class UserAuthImpl
        extends AbstractService
        implements UserAuth {

    private final Promise<Boolean, UserAuthException> authenticated
            = new Promise<Boolean, UserAuthException>("authenticated", UserAuthException.chainer);

    // Externally available
    private volatile String banner = "";
    private volatile boolean partialSuccess = false;
    private volatile List<String> allowedMethods = new LinkedList<String>();

    // Internal state
    private AuthMethod currentMethod;

    public UserAuthImpl(Transport trans) {
        super("ssh-userauth", trans);
    }

    @Override
    public boolean authenticate(String username, Service nextService, AuthMethod method, int timeoutMs)
            throws UserAuthException, TransportException {
        final boolean outcome;

        authenticated.lock();
        try {
            super.request(); // Request "ssh-userauth" service (if not already active)

            currentMethod = method;
            currentMethod.init(makeAuthParams(username, nextService));
            authenticated.clear();
            log.debug("Trying `{}` auth...", method.getName());
            currentMethod.request();
            outcome = authenticated.retrieve(timeoutMs, TimeUnit.MILLISECONDS);

            if (outcome) {
                log.debug("`{}` auth successful", method.getName());
                trans.setAuthenticated(); // So it can put delayed compression into force if applicable
                trans.setService(nextService); // We aren't in charge anymore, next service is
            } else {
                log.debug("`{}` auth failed", method.getName());
            }

        } finally {
            currentMethod = null;
            authenticated.unlock();
        }

        return outcome;
    }

    @Override
    public String getBanner() {
        return banner;
    }

    @Override
    public boolean hadPartialSuccess() {
        return partialSuccess;
    }

    @Override
    public Iterable<String> getAllowedMethods() {
        return Collections.unmodifiableList(allowedMethods);
    }

    @Override
    public void handle(Message msg, SSHPacket buf)
            throws SSHException {
        if (!msg.in(50, 80)) // ssh-userauth packets have message numbers between 50-80
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);

        authenticated.lock();
        try {
            switch (msg) {

                case USERAUTH_BANNER: {
                    banner = buf.readString();
                }
                break;

                case USERAUTH_SUCCESS: {
                    authenticated.deliver(true);
                }
                break;

                case USERAUTH_FAILURE: {
                    allowedMethods = Arrays.asList(buf.readString().split(","));
                    partialSuccess |= buf.readBoolean();
                    if (allowedMethods.contains(currentMethod.getName()) && currentMethod.shouldRetry()) {
                        currentMethod.request();
                    } else {
                        authenticated.deliver(false);
                    }
                }
                break;

                default: {
                    log.debug("Asking `{}` method to handle {} packet", currentMethod.getName(), msg);
                    try {
                        currentMethod.handle(msg, buf);
                    } catch (UserAuthException e) {
                        authenticated.deliverError(e);
                    }
                }

            }
        } finally {
            authenticated.unlock();
        }
    }

    @Override
    public void notifyError(SSHException error) {
        super.notifyError(error);
        authenticated.deliverError(error);
    }

    private AuthParams makeAuthParams(final String username, final Service nextService) {
        return new AuthParams() {

            @Override
            public String getNextServiceName() {
                return nextService.getName();
            }

            @Override
            public Transport getTransport() {
                return trans;
            }

            @Override
            public String getUsername() {
                return username;
            }

        };
    }

}
