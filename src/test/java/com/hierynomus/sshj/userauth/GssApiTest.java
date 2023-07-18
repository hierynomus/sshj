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
package com.hierynomus.sshj.userauth;

import com.hierynomus.sshj.test.SshServerExtension;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.method.AuthGssApiWithMic;
import net.schmizz.sshj.util.gss.BogusGSSManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class GssApiTest {

    @RegisterExtension
    public SshServerExtension fixture = new SshServerExtension();

    private static final String LOGIN_CONTEXT_NAME = "TestLoginContext";

    private static class TestAuthConfiguration extends Configuration {
        private AppConfigurationEntry entry = new AppConfigurationEntry(
                "testLoginModule",
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                Collections.<String, Object> emptyMap());

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            if (name.equals(LOGIN_CONTEXT_NAME)) {
                return new AppConfigurationEntry[] { entry };
            } else {
                return new AppConfigurationEntry[0];
            }
        }
    }

    @Test
    public void authenticated() throws Exception {
        AuthGssApiWithMic authMethod = new AuthGssApiWithMic(
                new LoginContext(LOGIN_CONTEXT_NAME, null, null, new TestAuthConfiguration()),
                Collections.singletonList(BogusGSSManager.KRB5_MECH),
                new BogusGSSManager());

        SSHClient defaultClient = fixture.setupConnectedDefaultClient();
        defaultClient.auth("user", authMethod);
        assertTrue(defaultClient.isAuthenticated());
    }

}
