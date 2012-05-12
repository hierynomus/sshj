package net.schmizz.sshj.sftp;

import org.junit.Test;

import java.io.IOException;

import static junit.framework.Assert.assertEquals;

public class PathHelperTest {

    private final PathHelper helper = new PathHelper(new PathHelper.Canonicalizer() {
        /**
         * Very basic, it does not try to canonicalize relative bits in the middle of a path.
         */
        @Override
        public String canonicalize(String path)
                throws IOException {
            if (path.equals("") || path.equals(".") || path.equals("./"))
                return "/home/me";
            if (path.equals("..") || path.equals("../"))
                return "/home";
            return path;
        }
    }, "/");

    @Test
    public void empty()
            throws IOException {
        final PathComponents comp = helper.getComponents("");
        assertEquals("me", comp.getName());
        assertEquals("/home", comp.getParent());
    }

    @Test
    public void root()
            throws IOException {
        final PathComponents comp = helper.getComponents("/");
        assertEquals("", comp.getName());
        assertEquals("", comp.getParent());
    }

    @Test
    public void dot()
            throws IOException {
        final PathComponents comp = helper.getComponents(".");
        assertEquals("me", comp.getName());
        assertEquals("/home", comp.getParent());
    }

    @Test
    public void dotDot()
            throws IOException {
        final PathComponents comp = helper.getComponents("..");
        assertEquals("home", comp.getName());
        assertEquals("", comp.getParent());
    }

    @Test
    public void fileInHomeDir()
            throws IOException {
        final PathComponents comp = helper.getComponents("somefile");
        assertEquals("somefile", comp.getName());
        assertEquals("", comp.getParent());
    }

    @Test
    public void fileSomeLevelsDeep()
            throws IOException {
        final PathComponents comp = helper.getComponents("/home/me/../somedir/somefile");
        assertEquals("somefile", comp.getName());
        assertEquals("/home/me/../somedir", comp.getParent());
    }

}
