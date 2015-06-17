package com.hierynomus.sshj.userauth;

import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.method.AuthGssApiWithMic;
import net.schmizz.sshj.util.gss.BogusGSSManager;
import org.junit.Rule;
import org.junit.Test;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import java.util.Collections;

import static org.junit.Assert.assertTrue;

public class GssApiTest {

    @Rule
    public SshFixture fixture = new SshFixture();

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
