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

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.Console;

import static org.junit.jupiter.api.Assertions.*;

public class TestConsolePasswordFinder {

    private static final String FORMAT = "%s";

    @Test
    public void testReqPassword() {
        char[] expectedPassword = "password".toCharArray();

        Console console = Mockito.mock(Console.class);
        Mockito.when(console.readPassword(Mockito.anyString(), Mockito.any()))
                .thenReturn(expectedPassword);

        Resource resource = Mockito.mock(Resource.class);
        char[] password = new ConsolePasswordFinder(console).reqPassword(resource);

        assertArrayEquals(expectedPassword, password, "Password should match mocked return value");
        Mockito.verifyNoMoreInteractions(resource);
    }

    @Test
    public void testReqPasswordNullConsole() {
        Resource<?> resource = Mockito.mock(Resource.class);
        char[] password = new ConsolePasswordFinder(null, FORMAT, 1).reqPassword(resource);

        assertNull(password, "Password should be null with null console");
        Mockito.verifyNoMoreInteractions(resource);
    }

    @Test
    public void testShouldRetry() {
        Resource<String> resource = new PrivateKeyStringResource("");
        ConsolePasswordFinder finder = new ConsolePasswordFinder(null, FORMAT, 1);
        assertTrue(finder.shouldRetry(resource), "Should allow a retry at first");

        finder.reqPassword(resource);
        assertFalse(finder.shouldRetry(resource), "Should stop allowing retries after one interaction");
    }

    @Test
    public void testPromptFormat() {
        assertNotNull(
                new ConsolePasswordFinder(null, "", 1), "Empty format should create valid ConsolePasswordFinder");
        assertNotNull(
                new ConsolePasswordFinder(null, FORMAT, 1), "Single-string format should create valid ConsolePasswordFinder");
    }

    @Test
    public void testPromptFormatTooManyMarkers() {
        assertThrows(IllegalArgumentException.class, () -> new ConsolePasswordFinder(null, "%s%s", 1));
    }

    @Test
    public void testPromptFormatWrongMarkerType() {
        assertThrows(IllegalArgumentException.class, () -> new ConsolePasswordFinder(null, "%d", 1));
    }

}
