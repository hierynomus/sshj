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
package net.schmizz.sshj.userauth.password;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.Console;

public class TestConsolePasswordFinder {

    @Test
    public void testReqPassword() {
        char[] expectedPassword = "password".toCharArray();

        Console console = Mockito.mock(Console.class);
        Mockito.when(console.readPassword(Mockito.anyString(), Mockito.any()))
                .thenReturn(expectedPassword);

        Resource resource = Mockito.mock(Resource.class);
        char[] password = ConsolePasswordFinder.builder()
                .setConsole(console)
                .build()
                .reqPassword(resource);

        Assert.assertArrayEquals("Password should match mocked return value",
                expectedPassword, password);
        Mockito.verifyNoMoreInteractions(resource);
    }

    @Test
    public void testReqPasswordNullConsole() {
        Resource<?> resource = Mockito.mock(Resource.class);
        char[] password = ConsolePasswordFinder.builder()
                .setConsole(null)
                .build()
                .reqPassword(resource);

        Assert.assertNull("Password should be null with null console", password);
        Mockito.verifyNoMoreInteractions(resource);
    }

    @Test
    public void testShouldRetry() {
        Resource<String> resource = new PrivateKeyStringResource("");
        ConsolePasswordFinder finder = ConsolePasswordFinder.builder()
                .setConsole(null)
                .setMaxTries(1)
                .build();
        Assert.assertTrue("Should allow a retry at first", finder.shouldRetry(resource));

        finder.reqPassword(resource);
        Assert.assertFalse("Should stop allowing retries after one interaction", finder.shouldRetry(resource));
    }

    @Test
    public void testPromptFormat() {
        Assert.assertNotNull(
                "Empty format should create valid ConsolePasswordFinder",
                ConsolePasswordFinder.builder().setPromptFormat("").build());
        Assert.assertNotNull(
                "Single-string format should create valid ConsolePasswordFinder",
                ConsolePasswordFinder.builder().setPromptFormat("%s").build());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPromptFormatTooManyMarkers() {
        ConsolePasswordFinder.builder().setPromptFormat("%s%s");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPromptFormatWrongMarkerType() {
        ConsolePasswordFinder.builder().setPromptFormat("%d");
    }

}
