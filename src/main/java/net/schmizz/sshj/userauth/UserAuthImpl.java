/*
 * Copyright 2010 Shikhar Bhushan
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
 *
 * This file may incorporate work covered by the following copyright and
 * permission notice:
 *
 *     Licensed to the Apache Software Foundation (ASF) under one
 *     or more contributor license agreements.  See the NOTICE file
 *     distributed with this work for additional information
 *     regarding copyright ownership.  The ASF licenses this file
 *     to you under the Apache License, Version 2.0 (the
 *     "License"); you may not use this file except in compliance
 *     with the License.  You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing,
 *      software distributed under the License is distributed on an
 *      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *      KIND, either express or implied.  See the License for the
 *      specific language governing permissions and limitations
 *      under the License.
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
public class UserAuthImpl extends AbstractService implements UserAuth, AuthParams {

    private final Set<String> allowed = new HashSet<String>();

    private final Deque<UserAuthException> savedEx = new ArrayDeque<UserAuthException>();

    private final Event<UserAuthException> result = new Event<UserAuthException>("userauth result",
            UserAuthException.chainer);

    private String username;
    private AuthMethod currentMethod;
    private Service nextService;

    private boolean firstAttempt = true;

    private volatile String banner;
    private volatile boolean partialSuccess;

    public UserAuthImpl(Transport trans) {
        super("ssh-userauth", trans);
    }

    // synchronized for mutual exclusion; ensure one authenticate() ever in progress

    public synchronized void authenticate(String username, Service nextService, Iterable<AuthMethod> methods)
            throws UserAuthException, TransportException {
        clearState();

        this.username = username;
        this.nextService = nextService;

        // Request "ssh-userauth" service (if not already active)
        request();

        if (firstAttempt) { // Assume all allowed
            for (AuthMethod meth : methods)
                allowed.add(meth.getName());
            firstAttempt = false;
        }

        try {

            for (AuthMethod meth : methods)

                if (allowed.contains(meth.getName())) {

                    log.info("Trying `{}` auth...", meth.getName());

                    boolean success = false;
                    try {
                        success = tryWith(meth);
                    } catch (UserAuthException e) {
                        // Give other method a shot
                        saveException(e);
                    }

                    if (success) {
                        log.info("`{}` auth successful", meth.getName());
                        return;
                    } else
                        log.info("`{}` auth failed", meth.getName());

                } else
                    saveException(currentMethod.getName() + " auth not allowed by server");

        } finally {
            currentMethod = null;
        }

        log.debug("Had {} saved exception(s)", savedEx.size());
        throw new UserAuthException("Exhausted available authentication methods", savedEx.peek());
    }

    public String getBanner() {
        return banner;
    }

    public String getNextServiceName() {
        return nextService.getName();
    }

    public Transport getTransport() {
        return trans;
    }

    /**
     * Returns the exceptions that occured during authentication process but were ignored because more method were
     * available for trying.
     *
     * @return deque of saved exceptions
     */
    public Deque<UserAuthException> getSavedExceptions() {
        return savedEx;
    }

    public String getUsername() {
        return username;
    }

    public boolean hadPartialSuccess() {
        return partialSuccess;
    }

    @Override
    public void handle(Message msg, SSHPacket buf) throws SSHException {
        if (!msg.in(50, 80)) // ssh-userauth packets have message numbers between 50-80
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);

        switch (msg) {

            case USERAUTH_BANNER:
                gotBanner(buf);
                break;

            case USERAUTH_SUCCESS:
                gotSuccess();
                break;

            case USERAUTH_FAILURE:
                gotFailure(buf);
                break;

            default:
                gotUnknown(msg, buf);

        }
    }

    @Override
    public void notifyError(SSHException error) {
        super.notifyError(error);
        result.error(error);
    }

    private void clearState() {
        allowed.clear();
        savedEx.clear();
        banner = null;
    }

    private void gotBanner(SSHPacket buf) {
        banner = buf.readString();
    }

    private void gotFailure(SSHPacket buf) throws UserAuthException, TransportException {
        allowed.clear();
        allowed.addAll(Arrays.<String>asList(buf.readString().split(",")));
        partialSuccess |= buf.readBoolean();
        if (allowed.contains(currentMethod.getName()) && currentMethod.shouldRetry())
            currentMethod.request();
        else {
            saveException(currentMethod.getName() + " auth failed");
            result.set(false);
        }
    }

    private void gotSuccess() {
        trans.setAuthenticated(); // So it can put delayed compression into force if applicable
        trans.setService(nextService); // We aren't in charge anymore, next service is
        result.set(true);
    }

    private void gotUnknown(Message msg, SSHPacket buf) throws SSHException {
        if (currentMethod == null || result == null) {
            trans.sendUnimplemented();
            return;
        }

        log.debug("Asking {} method to handle {} packet", currentMethod.getName(), msg);
        try {
            currentMethod.handle(msg, buf);
        } catch (UserAuthException e) {
            result.error(e);
        }
    }

    private void saveException(String msg) {
        saveException(new UserAuthException(msg));
    }

    private void saveException(UserAuthException e) {
        log.error("Saving for later - {}", e.toString());
        savedEx.push(e);
    }

    private boolean tryWith(AuthMethod meth) throws UserAuthException, TransportException {
        currentMethod = meth;
        result.clear();
        meth.init(this);
        meth.request();
        return result.get(timeout, TimeUnit.SECONDS);
    }

}
