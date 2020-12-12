package net.schmizz.sshj.connection.channel.direct;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

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

}
