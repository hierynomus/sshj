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
package net.schmizz.sshj.connection.channel.direct;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class ParametersTest {

    @Test
    public void testConstructedFields() {
        final Parameters p = new Parameters("127.0.0.1", 8080, "github.com", 80);
        assertEquals("127.0.0.1", p.getLocalHost());
        assertEquals(8080, p.getLocalPort());
        assertEquals("github.com", p.getRemoteHost());
        assertEquals(80, p.getRemotePort());
    }

    @Test
    public void testFieldsEquality() {
        final Parameters first = new Parameters("127.0.0.1", 8080, "github.com", 80);
        final Parameters second = new Parameters("127.0.0.1", 8080, "github.com", 80);
        assertEquals(first.getLocalHost(), second.getLocalHost());
        assertEquals(first.getLocalPort(), second.getLocalPort());
        assertEquals(first.getRemoteHost(), second.getRemoteHost());
        assertEquals(first.getRemotePort(), second.getRemotePort());
    }

    @Test
    public void testInstanceIdentity() {
        final Parameters first = new Parameters("127.0.0.1", 8080, "github.com", 80);
        final Parameters second = new Parameters("127.0.0.1", 8080, "github.com", 80);
        assertTrue(first == first);
        assertTrue(second == second);
        assertFalse(first == second);
    }

    @Test
    public void testInstanceEquality() {
        final Parameters first = new Parameters("127.0.0.1", 8080, "github.com", 80);
        final Parameters second = new Parameters("127.0.0.1", 8080, "github.com", 80);
        assertFalse(first == second);
        assertTrue(first.equals(second));
        assertTrue(second.equals(first));
        assertEquals(first, second);
    }

    @Test
    public void testHashCode() {
        final Parameters first = new Parameters("127.0.0.1", 8080, "github.com", 80);
        final Parameters second = new Parameters("127.0.0.1", 8080, "github.com", 80);
        assertEquals(first.hashCode(), first.hashCode());
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals(second.hashCode(), second.hashCode());

        final Parameters third = new Parameters("127.0.0.1", 443, "github.com", 80);
        assertEquals(third.hashCode(), third.hashCode());
        assertNotEquals(first.hashCode(), third.hashCode());
    }

    @Test
    public void testHashMapApplicability() {
        final Parameters first = new Parameters("127.0.0.1", 8080, "github.com", 80);

        final Map<Parameters, String> map = new HashMap<>();
        assertFalse(map.containsKey(first));

        final String none = map.put(first, "is now in the map");
        assertNull(none);
        assertTrue(map.containsKey(first));
        assertEquals("is now in the map", map.get(first));

        final Parameters second = new Parameters("127.0.0.1", 8080, "github.com", 80);
        assertTrue(map.containsKey(second));
        assertEquals("is now in the map", map.get(second));

        final String current = map.putIfAbsent(second, "is again in the map");
        assertEquals("is now in the map", current);
        assertEquals("is now in the map", map.get(first));
        assertEquals("is now in the map", map.get(second));

        final String previous = map.put(second, "is again in the map");
        assertEquals("is now in the map", previous);
        assertEquals("is again in the map", map.get(first));
        assertEquals("is again in the map", map.get(second));

        final Parameters third = new Parameters("127.0.0.1", 443, "github.com", 80);
        assertFalse(map.containsKey(third));
        assertNull(map.get(third));
    }

    @Test
    public void testToString() {
        final Parameters first = new Parameters("127.0.0.1", 8080, "github.com", 443);
        assertNotNull(first.toString());
        assertFalse(first.toString().isBlank());
        assertTrue(first.toString().contains("127.0.0.1"));
        assertTrue(first.toString().contains("8080"));
        assertTrue(first.toString().contains("github.com"));
        assertTrue(first.toString().contains("443"));
    }

}
