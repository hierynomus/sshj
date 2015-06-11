package net.schmizz.sshj.userauth;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Collections;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import net.schmizz.sshj.userauth.method.AuthGssApiWithMic;
import net.schmizz.sshj.util.BasicFixture;
import net.schmizz.sshj.util.gss.BogusGSSAuthenticator;
import net.schmizz.sshj.util.gss.BogusGSSManager;

public class GssApiTest {

    private static final String LOGIN_CONTEXT_NAME = "TestLoginContext";

    private static class TestAuthConfiguration extends Configuration {
        private AppConfigurationEntry entry = new AppConfigurationEntry(
                "testLoginModule",
                LoginModuleControlFlag.REQUIRED,
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

    private final BasicFixture fixture = new BasicFixture();

    @Before
    public void setUp() throws Exception {
        fixture.setGssAuthenticator(new BogusGSSAuthenticator());
        fixture.init(false);
    }

    @After
    public void tearDown() throws IOException, InterruptedException {
        fixture.done();
    }

    @Test
    public void authenticated() throws Exception {
        AuthGssApiWithMic authMethod = new AuthGssApiWithMic(
                new LoginContext(LOGIN_CONTEXT_NAME, null, null, new TestAuthConfiguration()),
                Collections.singletonList(BogusGSSManager.KRB5_MECH),
                new BogusGSSManager());

        fixture.getClient().auth("user", authMethod);
        assertTrue(fixture.getClient().isAuthenticated());
    }

}
