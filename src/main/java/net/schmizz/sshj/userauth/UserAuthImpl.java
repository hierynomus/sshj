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

import net.schmizz.concurrent.Event;
import net.schmizz.sshj.AbstractService;
import net.schmizz.sshj.Service;
import net.schmizz.sshj.common.DisconnectReason;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.method.AuthMethod;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** {@link UserAuth} implementation. */
public class UserAuthImpl
        extends AbstractService
        implements UserAuth {

    private final Event<UserAuthException> authenticated
            = new Event<UserAuthException>("authenticated", UserAuthException.chainer);

    // Externally available
    private final Deque<UserAuthException> savedEx = new ArrayDeque<UserAuthException>();
    private volatile String banner = "";
    private volatile boolean partialSuccess;

    // Internal state
    private Set<String> allowedMethods;
    private AuthMethod currentMethod;

    public UserAuthImpl(Transport trans) {
        super("ssh-userauth", trans);
    }

    // synchronized for mutual exclusion; ensure only one authenticate() ever in progress
    @Override
    public synchronized void authenticate(final String username,
                                          final Service nextService,
                                          final Iterable<AuthMethod> methods)
            throws UserAuthException, TransportException {
        savedEx.clear();

        // Request "ssh-userauth" service (if not already active)
        super.request();

        if (allowedMethods == null) { // Assume all are allowed
            allowedMethods = new HashSet<String>();
            for (AuthMethod meth : methods)
                allowedMethods.add(meth.getName());
        }

        try {

            final AuthParams authParams = makeAuthParams(username, nextService);

            for (AuthMethod meth : methods) {

                if (!allowedMethods.contains(meth.getName())) {
                    saveException(new UserAuthException(meth.getName() + " auth not allowed by server"));
                    continue;
                }

                log.info("Trying `{}` auth...", meth.getName());
                authenticated.clear();
                currentMethod = meth;

                try {

                    currentMethod.init(authParams);
                    currentMethod.request();
                    authenticated.await(timeout, TimeUnit.SECONDS);

                } catch (UserAuthException e) {
                    log.info("`{}` auth failed", meth.getName());
                    // Give other methods a shot
                    saveException(e);
                    continue;
                }

                log.info("`{}` auth successful", meth.getName());
                trans.setAuthenticated(); // So it can put delayed compression into force if applicable
                trans.setService(nextService); // We aren't in charge anymore, next service is
                return;

            }

        } finally {
            currentMethod = null;
        }

        log.debug("Had {} saved exception(s)", savedEx.size());
        throw new UserAuthException("Exhausted available authentication methods", savedEx.peek());
    }

    @Override
    public synchronized Deque<UserAuthException> getSavedExceptions() {
        return savedEx;
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
    public void handle(Message msg, SSHPacket buf)
            throws SSHException {
        if (!msg.in(50, 80)) // ssh-userauth packets have message numbers between 50-80
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);

        switch (msg) {

            case USERAUTH_BANNER: {
                banner = buf.readString();
            }
            break;

            case USERAUTH_SUCCESS: {
                authenticated.set();
            }
            break;

            case USERAUTH_FAILURE: {
                allowedMethods.clear();
                allowedMethods.addAll(Arrays.<String>asList(buf.readString().split(",")));
                partialSuccess |= buf.readBoolean();
                if (allowedMethods.contains(currentMethod.getName()) && currentMethod.shouldRetry()) {
                    currentMethod.request();
                } else {
                    authenticated.deliverError(new UserAuthException(currentMethod.getName() + " auth failed"));
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

    private void saveException(UserAuthException e) {
        log.debug("Saving for later - {}", e.toString());
        savedEx.push(e);
    }

}
