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
package net.schmizz.sshj.userauth.method;

import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.password.AccountResource;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUpdateProvider;
import net.schmizz.sshj.userauth.password.Resource;

/** Implements the {@code password} authentication method. Password-change request handling is not currently supported. */
public class AuthPassword
        extends AbstractAuthMethod {

    private final PasswordFinder pwdf;

    private static final PasswordUpdateProvider nullProvider = new PasswordUpdateProvider() {
        @Override
        public char[] provideNewPassword(Resource<?> resource, String prompt) {
            return null;
        }

        @Override
        public boolean shouldRetry(Resource<?> resource) {
            return false;
        }
    };

    private final PasswordUpdateProvider newPasswordProvider;

    public AuthPassword(PasswordFinder pwdf) {
        this(pwdf, nullProvider);
    }

    public AuthPassword(PasswordFinder pwdf, PasswordUpdateProvider newPasswordProvider) {
        super("password");
        this.pwdf = pwdf;
        this.newPasswordProvider = newPasswordProvider;
    }

    @Override
    public SSHPacket buildReq()
            throws UserAuthException {
        final AccountResource accountResource = makeAccountResource();
        log.debug("Requesting password for {}", accountResource);
        return super.buildReq() // the generic stuff
                .putBoolean(false) // no, we are not responding to a CHANGEREQ
                .putSensitiveString(pwdf.reqPassword(accountResource));
    }

    @Override
    public void handle(Message cmd, SSHPacket buf)
            throws UserAuthException, TransportException {
        if (cmd == Message.USERAUTH_60 && newPasswordProvider != null) {
            log.info("Received SSH_MSG_USERAUTH_PASSWD_CHANGEREQ.");
            try {
                String prompt = buf.readString();
                buf.readString(); // lang-tag
                AccountResource resource = makeAccountResource();
                char[] newPassword = newPasswordProvider.provideNewPassword(resource, prompt);
                SSHPacket sshPacket = super.buildReq().putBoolean(true).putSensitiveString(pwdf.reqPassword(resource)).putSensitiveString(newPassword);
                params.getTransport().write(sshPacket);
            } catch (Buffer.BufferException e) {
                throw new TransportException(e);
            }
        } else if (cmd == Message.USERAUTH_60) {
            throw new UserAuthException("Password change request received; unsupported operation (newPassword was 'null')");
        } else {
            super.handle(cmd, buf);
        }
    }

    /**
     * Returns {@code true} if the associated {@link PasswordFinder} tells that we should retry with a new password that
     * it will supply.
     */
    @Override
    public boolean shouldRetry() {
        AccountResource accountResource = makeAccountResource();
        return newPasswordProvider.shouldRetry(accountResource) || pwdf.shouldRetry(accountResource);
    }

}
