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
            if ("".equals(path) || ".".equals(path) || "./".equals(path))
                return "/home/me";
            if ("..".equals(path) || "../".equals(path))
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
