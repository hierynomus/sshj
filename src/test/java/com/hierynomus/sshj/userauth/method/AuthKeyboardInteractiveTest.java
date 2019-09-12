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
package com.hierynomus.sshj.userauth.method;

import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.method.AuthKeyboardInteractive;
import net.schmizz.sshj.userauth.method.ChallengeResponseProvider;
import net.schmizz.sshj.userauth.password.Resource;
import org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.keyboard.UserAuthKeyboardInteractive;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;

public class AuthKeyboardInteractiveTest {
    @Rule
    public SshFixture fixture = new SshFixture(false);

    @Before
    public void setKeyboardInteractiveAuthenticator() throws IOException {
        fixture.getServer().setUserAuthFactories(Collections.<NamedFactory<UserAuth>>singletonList(new NamedFactory<UserAuth>() {
            @Override
            public String getName() {
                return UserAuthKeyboardInteractiveFactory.NAME;
            }

            @Override
            public UserAuth get() {
                return new UserAuthKeyboardInteractive();
            }

            @Override
            public UserAuth create() {
                return get();
            }
        }));
        fixture.getServer().setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session) {
                return password.equals(username);
            }
        });
        fixture.getServer().start();
    }

    @Test
    public void shouldEncodePasswordsAsUtf8() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        final String userAndPassword = "øæå";
        sshClient.auth(userAndPassword, new AuthKeyboardInteractive(new ChallengeResponseProvider() {
            @Override
            public List<String> getSubmethods() {
                return new ArrayList<String>();
            }

            @Override
            public void init(Resource resource, String name, String instruction) {
                // nothing
            }

            @Override
            public char[] getResponse(String prompt, boolean echo) {
                return userAndPassword.toCharArray();
            }

            @Override
            public boolean shouldRetry() {
                return false;
            }
        }));
        assertThat("Should have been authenticated", sshClient.isAuthenticated());
    }
}
