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

import net.schmizz.sshj.userauth.method.PasswordResponseProvider;
import net.schmizz.sshj.userauth.password.AccountResource;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import org.jetbrains.annotations.NotNull;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;
import java.util.regex.Pattern;

public class PasswordResponseProviderTest {
    private static final char[] PASSWORD = "the_password".toCharArray();
    private static final AccountResource ACCOUNT_RESOURCE = new AccountResource("user", "host");

    @Test
    public void shouldMatchCommonPrompts() {
        PasswordResponseProvider responseProvider = createDefaultResponseProvider(false);
        shouldMatch(responseProvider, "Password: ");
        shouldMatch(responseProvider, "password: ");
        shouldMatch(responseProvider, "Password:");
        shouldMatch(responseProvider, "password:");
        shouldMatch(responseProvider, "user@host's Password: ");
        shouldMatch(responseProvider, "user@host's password: ");
        shouldMatch(responseProvider, "user@host's Password:");
        shouldMatch(responseProvider, "user@host's password:");
        shouldMatch(responseProvider, "user@host: Password: ");
        shouldMatch(responseProvider, "(user@host) Password: ");
        shouldMatch(responseProvider, "any prefix Password for user@host: ");
        shouldMatch(responseProvider, "any prefix password for user@host: ");
        shouldMatch(responseProvider, "any prefix Password for user@host:");
        shouldMatch(responseProvider, "any prefix password for user@host:");
    }

    @Test
    public void shouldNotMatchOtherPrompts() {
        PasswordResponseProvider responseProvider = createDefaultResponseProvider(false);
        shouldNotMatch(responseProvider, "Password");
        shouldNotMatch(responseProvider, "password");
        shouldNotMatch(responseProvider, "Password:  ");
        shouldNotMatch(responseProvider, "password: suffix");
        shouldNotMatch(responseProvider, "Password of user@host:");
        shouldNotMatch(responseProvider, "");
        shouldNotMatch(responseProvider, "password :");
        shouldNotMatch(responseProvider, "something else");
    }

    @Test
    public void shouldPassRetry() {
        Assert.assertFalse(createDefaultResponseProvider(false).shouldRetry());
        Assert.assertTrue(createDefaultResponseProvider(true).shouldRetry());
    }

    @Test
    public void shouldHaveNoSubmethods() {
        Assert.assertEquals(createDefaultResponseProvider(true).getSubmethods(), Collections.emptyList());
    }

    @Test
    public void shouldWorkWithCustomPattern() {
        PasswordFinder passwordFinder = new TestPasswordFinder(true);
        PasswordResponseProvider responseProvider = new PasswordResponseProvider(passwordFinder, Pattern.compile(".*custom.*"));
        responseProvider.init(ACCOUNT_RESOURCE, "name", "instruction");
        shouldMatch(responseProvider, "prefix custom suffix: ");
        shouldNotMatch(responseProvider, "something else");
    }

    private static void shouldMatch(PasswordResponseProvider responseProvider, String prompt) {
        checkPrompt(responseProvider, prompt, PASSWORD);
    }

    private static void shouldNotMatch(PasswordResponseProvider responseProvider, String prompt) {
        checkPrompt(responseProvider, prompt, new char[0]);
    }

    private static void checkPrompt(PasswordResponseProvider responseProvider, String prompt, char[] expected) {
        Assert.assertArrayEquals("Prompt '" + prompt + "'", expected, responseProvider.getResponse(prompt, false));
    }

    @NotNull
    private static PasswordResponseProvider createDefaultResponseProvider(final boolean shouldRetry) {
        PasswordFinder passwordFinder = new TestPasswordFinder(shouldRetry);
        PasswordResponseProvider responseProvider = new PasswordResponseProvider(passwordFinder);
        responseProvider.init(ACCOUNT_RESOURCE, "name", "instruction");
        return responseProvider;
    }

    private static class TestPasswordFinder implements PasswordFinder {
        private final boolean shouldRetry;

        public TestPasswordFinder(boolean shouldRetry) {
            this.shouldRetry = shouldRetry;
        }

        @Override
        public char[] reqPassword(Resource<?> resource) {
            Assert.assertEquals(resource, ACCOUNT_RESOURCE);
            return PASSWORD;
        }

        @Override
        public boolean shouldRetry(Resource<?> resource) {
            Assert.assertEquals(resource, ACCOUNT_RESOURCE);
            return shouldRetry;
        }
    }
}
