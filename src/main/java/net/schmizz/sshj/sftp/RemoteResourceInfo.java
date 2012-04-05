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

public class RemoteResourceInfo {

    private final PathComponents comps;
    private final FileAttributes attrs;

    public RemoteResourceInfo(PathComponents comps, FileAttributes attrs) {
        this.comps = comps;
        this.attrs = attrs;
    }

    public String getPath() {
        return comps.getPath();
    }

    public String getParent() {
        return comps.getParent();
    }

    public String getName() {
        return comps.getName();
    }

    public FileAttributes getAttributes() {
        return attrs;
    }

    public boolean isRegularFile() {
        return attrs.getType() == FileMode.Type.REGULAR;
    }

    public boolean isDirectory() {
        return attrs.getType() == FileMode.Type.DIRECTORY;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RemoteResourceInfo && (comps.equals(((RemoteResourceInfo) o).comps));
    }

    @Override
    public int hashCode() {
        return comps.hashCode();
    }

    @Override
    public String toString() {
        return "[" + attrs.getType() + "] " + getPath();
    }

}
