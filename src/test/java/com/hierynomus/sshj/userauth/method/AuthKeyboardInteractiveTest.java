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

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.method.AuthKeyboardInteractive;
import net.schmizz.sshj.userauth.method.ChallengeResponseProvider;
import net.schmizz.sshj.userauth.password.Resource;
import org.apache.sshd.server.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;

public class AuthKeyboardInteractiveTest {
    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension(false);

    @BeforeEach
    public void setKeyboardInteractiveAuthenticator() throws IOException {
        fixture.getServer().setUserAuthFactories(Collections.singletonList(new UserAuthKeyboardInteractiveFactory()));
        fixture.getServer().setPasswordAuthenticator(AcceptAllPasswordAuthenticator.INSTANCE);
        fixture.getServer().start();
    }

    @Test
    public void shouldEncodePasswordsAsUtf8() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        final String userAndPassword = "øæå";
        sshClient.auth(userAndPassword, new AuthKeyboardInteractive(new ChallengeResponseProvider() {
            @Override
            public List<String> getSubmethods() {
                return new ArrayList<>();
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
