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
 */
package net.schmizz.sshj.userauth.method;

import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.AuthParams;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.password.AccountResource;
import net.schmizz.sshj.userauth.password.Resource;

import java.util.ArrayList;
import java.util.List;

/** Implements the {@code keyboard-interactive} authentication method. */
public class AuthChallengeResponse
        extends AbstractAuthMethod {

    private final ChallengeResponseProvider provider;
    private Resource resource;

    public AuthChallengeResponse(ChallengeResponseProvider provider) {
        super("keyboard-interactive");
        this.provider = provider;
    }

    @Override
    public void init(AuthParams params) {
        super.init(params);
        resource = new AccountResource(params.getUsername(), params.getTransport().getRemoteHost());
    }

    @Override
    public SSHPacket buildReq()
            throws UserAuthException {
        return super.buildReq() // the generic stuff
                .putString("") // lang-tag
                .putString(getCommaSeparatedSubmethodList());
    }

    private String getCommaSeparatedSubmethodList() {
        StringBuilder sb = new StringBuilder();
        for (String submethod : provider.getSubmethods()) {
            if (sb.length() > 0)
                sb.append(",");
            sb.append(submethod);
        }
        return sb.toString();
    }

    @Override
    public void handle(Message cmd, SSHPacket buf)
            throws UserAuthException, TransportException {
        if (cmd == Message.USERAUTH_60) {
            provider.init(resource, buf.readString(), buf.readString());
            buf.readString(); // lang-tag
            final int numPrompts = buf.readInt();
            final List<String> userReplies = new ArrayList<String>(numPrompts);
            for (int i = 0; i < numPrompts; i++) {
                userReplies.add(provider.getResponse(buf.readString(), buf.readBoolean()));
            }
            respond(userReplies);
        } else
            super.handle(cmd, buf);
    }

    private void respond(List<String> userReplies)
            throws TransportException {
        final SSHPacket pkt = new SSHPacket(Message.USERAUTH_INFO_RESPONSE)
                .putInt(userReplies.size());
        for (String response : userReplies) {
            pkt.putString(response);
        }
        params.getTransport().write(pkt);
    }

    /**
     * Returns {@code true} if the associated {@link net.schmizz.sshj.userauth.password.PasswordFinder} tells that we
     * should retry with a new password that it will supply.
     */
    @Override
    public boolean shouldRetry() {
        return provider.shouldRetry();
    }

}