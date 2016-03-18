package com.hierynomus.sshj.userauth.method;

import com.hierynomus.sshj.test.SshFixture;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.PasswordUpdateProvider;
import net.schmizz.sshj.userauth.password.Resource;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.auth.password.UserAuthPassword;
import org.apache.sshd.server.session.ServerSession;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.util.Collections;
import java.util.Stack;

import static org.hamcrest.MatcherAssert.assertThat;

public class AuthPasswordTest {

    @Rule
    public SshFixture fixture = new SshFixture(false);

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setPasswordAuthenticator() throws IOException {
        fixture.getServer().setUserAuthFactories(Collections.<NamedFactory<UserAuth>>singletonList(new NamedFactory<UserAuth>() {

            @Override
            public String getName() {
                return "password";
            }

            @Override
            public UserAuth create() {
                return new UserAuthPassword() {
                    @Override
                    protected Boolean handleClientPasswordChangeRequest(Buffer buffer, ServerSession session, String username, String oldPassword, String newPassword) throws Exception {
                        return checkPassword(buffer, session, username, newPassword);
                    }
                };
            }
        }));
        fixture.getServer().setPasswordAuthenticator(new PasswordAuthenticator() {
            @Override
            public boolean authenticate(String username, String password, ServerSession session) {
                if (password.equals("changeme")) {
                    throw new PasswordChangeRequiredException("Password was changeme", "Please provide your updated password", "en_US");
                } else {
                    return password.equals(username);
                }
            }
        });
        fixture.getServer().start();
    }

    @Test
    public void shouldNotHandlePasswordChangeIfNoPasswordUpdateProviderSet() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        expectedException.expect(UserAuthException.class);
        sshClient.authPassword("jeroen", "changeme");
    }

    @Test
    public void shouldHandlePasswordChange() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("jeroen", new PasswordFinder() {
            @Override
            public char[] reqPassword(Resource<?> resource) {
                return "changeme".toCharArray();
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                return false;
            }
        }, new StaticPasswordUpdateProvider("jeroen"));
        assertThat("Should be authenticated", sshClient.isAuthenticated());
    }

    @Test
    public void shouldHandlePasswordChangeWithWrongPassword() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        expectedException.expect(UserAuthException.class);
        sshClient.authPassword("jeroen", new PasswordFinder() {
            @Override
            public char[] reqPassword(Resource<?> resource) {
                return "changeme".toCharArray();
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                return false;
            }
        }, new StaticPasswordUpdateProvider("bad"));
        assertThat("Should not have authenticated", !sshClient.isAuthenticated());
    }

    @Test
    public void shouldHandlePasswordChangeWithWrongPasswordOnFirstAttempt() throws IOException {
        SSHClient sshClient = fixture.setupConnectedDefaultClient();
        sshClient.authPassword("jeroen", new PasswordFinder() {
            @Override
            public char[] reqPassword(Resource<?> resource) {
                return "changeme".toCharArray();
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                return false;
            }
        }, new StaticPasswordUpdateProvider("bad", "jeroen"));
        assertThat("Should have been authenticated", sshClient.isAuthenticated());
    }

    private static class StaticPasswordUpdateProvider implements PasswordUpdateProvider {
        private Stack<String> newPasswords = new Stack<>();

        public StaticPasswordUpdateProvider(String... newPasswords) {
            for (int i = newPasswords.length - 1; i >= 0; i--) {
                this.newPasswords.push(newPasswords[i]);
            }
        }


        @Override
        public char[] provideNewPassword(Resource<?> resource, String prompt) {
            return newPasswords.pop().toCharArray();
        }

        @Override
        public boolean shouldRetry(Resource<?> resource) {
            return !newPasswords.isEmpty();
        }
    }
}
