/*
 * Copyright 2010 Shikhar Bhushan
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

class PathComponents {

    public static String adjustForParent(String parent, String path) {
        return (path.startsWith("/")) ? path // Absolute path, nothing to adjust
                                      : (parent + (parent.endsWith("/") ? "" : "/") + path); // Relative path
    }

    private static String trimFinalSlash(String path) {
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }

    private final String parent;
    private final String name;
    private final String path;

    public PathComponents(String parent, String name) {
        this.parent = parent;
        this.name = name;
        this.path = adjustForParent(parent, name);
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
        if (o instanceof PathComponents) {
            final PathComponents that = (PathComponents) o;
            return (trimFinalSlash(path).equals(trimFinalSlash(that.path)));
        }

        return false;
    }

    @Override
    public int hashCode() {
        return trimFinalSlash(path).hashCode();
    }

    @Override
    public String toString() {
        return "[parent=" + parent + "; name=" + name + "; path=" + path + "]";
    }

}