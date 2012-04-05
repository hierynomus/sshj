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

public class PathComponents {

    static String adjustForParent(String parent, String path, String pathSep) {
        return (path.startsWith(pathSep)) ? path // Absolute path, nothing to adjust
                : (parent + (parent.endsWith(pathSep) ? "" : pathSep) + path); // Relative path
    }

    static String trimTrailingSeparator(String somePath, String pathSep) {
        return somePath.endsWith(pathSep) ? somePath.substring(0, somePath.length() - pathSep.length()) : somePath;
    }

    private final String parent;
    private final String name;
    private final String path;

    public PathComponents(String parent, String name, String pathSep) {
        this.parent = parent;
        this.name = name;
        this.path = trimTrailingSeparator(adjustForParent(parent, name, pathSep), pathSep);
    }

    public String getParent() {
        return parent;
    }

    public String getName() {
        return name;
    }

    public String getPath() {
        return path;
    }

    @Override
    public boolean equals(Object o) {
        return this == o || ((o instanceof PathComponents) && path.equals(((PathComponents) o).path));
    }

    @Override
    public int hashCode() {
        return path.hashCode();
    }

    @Override
    public String toString() {
        return "[parent=" + parent + "; name=" + name + "; path=" + path + "]";
    }

}