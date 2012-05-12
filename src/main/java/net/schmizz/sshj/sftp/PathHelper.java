/*
 * Copyright 2010-2012 sshj contributors
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

import java.io.IOException;

public class PathHelper {

    public interface Canonicalizer {

        String canonicalize(String path)
                throws IOException;

    }

    public static final String DEFAULT_PATH_SEPARATOR = "/";

    private final Canonicalizer canonicalizer;
    private final String pathSep;

    private String dotDir;

    private synchronized String getDotDir() // cached
            throws IOException {
        return (dotDir != null) ? dotDir : (dotDir = canonicalizer.canonicalize("."));
    }

    public PathHelper(Canonicalizer canonicalizer, String pathSep) {
        this.canonicalizer = canonicalizer;
        this.pathSep = pathSep;
    }

    public String adjustForParent(String parent, String path) {
        return PathComponents.adjustForParent(parent, path, pathSep);
    }

    public String trimTrailingSeparator(String path) {
        return PathComponents.trimTrailingSeparator(path, pathSep);
    }

    public String getPathSeparator() {
        return pathSep;
    }

    public PathComponents getComponents(String parent, String name) {
        return new PathComponents(parent, name, pathSep);
    }

    /**
     * Divide the path into {@code PathComponents(parent, name)} while making sure {@code name != "." && name != ".."}
     *
     * @param path to convert
     *
     * @return PathComponents
     *
     * @throws IOException
     */
    public PathComponents getComponents(final String path)
            throws IOException {
        if (path.equals(pathSep))
            return getComponents("", "");

        if (path.isEmpty() || path.equals(".") || path.equals("." + pathSep))
            return getComponents(getDotDir());

        final String withoutTrailSep = trimTrailingSeparator(path);
        final int lastSep = withoutTrailSep.lastIndexOf(pathSep);
        final String parent = (lastSep == -1) ? "" : withoutTrailSep.substring(0, lastSep);
        final String name = (lastSep == -1) ? withoutTrailSep : withoutTrailSep.substring(lastSep + pathSep.length());

        if (name.equals(".") || name.equals("..")) {
            return getComponents(canonicalizer.canonicalize(path));
        } else {
            return getComponents(parent, name);
        }
    }

}