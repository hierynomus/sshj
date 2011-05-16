/*
 * Copyright 2010, 2011 sshj contributors
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

    public static final String DEFAULT_PATH_SEPARATOR = "/";

    private final SFTPEngine engine;
    private final String pathSep;

    private String dotDir;

    public PathHelper(SFTPEngine engine, String pathSep) {
        this.engine = engine;
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

    public PathComponents getComponents(String path)
            throws IOException {
        if (path.isEmpty() || path.equals("."))
            return getComponents(getDotDir());

        final int lastSlash = path.lastIndexOf(pathSep);

        if (lastSlash == -1) // Relative path
            if (path.equals(".."))
                return getComponents(canon(path));
            else
                return getComponents(getDotDir(), path);

        final String name = path.substring(lastSlash + pathSep.length());

        if (name.equals(".") || name.equals(".."))
            return getComponents(canon(path));
        else {
            final String parent = path.substring(0, lastSlash);
            return getComponents(parent, name);
        }
    }

    private synchronized String getDotDir()
            throws IOException {
        return (dotDir != null) ? dotDir : (dotDir = canon("."));
    }

    private String canon(String path)
            throws IOException {
        return engine.canonicalize(path);
    }

}