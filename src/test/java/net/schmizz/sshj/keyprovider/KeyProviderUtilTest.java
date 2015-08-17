package net.schmizz.sshj.keyprovider;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil;

public class KeyProviderUtilTest {

    private static final File ROOT = new File("src/test/resources/keyformats");

    @Test
    public void testOpenSsh() throws IOException {
        KeyFormat format = KeyProviderUtil.detectKeyFileFormat(new File(ROOT, "openssh"));
        assertEquals(KeyFormat.OpenSSH, format);
    }

    @Test
    public void testPkcs8() throws IOException {
        KeyFormat format = KeyProviderUtil.detectKeyFileFormat(new File(ROOT, "pkcs8"));
        assertEquals(KeyFormat.PKCS8, format);
    }

    @Test
    public void testPutty() throws IOException {
        KeyFormat format = KeyProviderUtil.detectKeyFileFormat(new File(ROOT, "putty"));
        assertEquals(KeyFormat.PuTTY, format);
    }

    @Test
    public void testSkipsBlankLines() throws IOException {
        KeyFormat format = KeyProviderUtil.detectKeyFileFormat(new File(ROOT, "pkcs8-blanks"));
        assertEquals(KeyFormat.PKCS8, format);
    }
}
