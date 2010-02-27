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
package net.schmizz.sshj.xfer;

import java.io.File;
import java.io.IOException;


/** Default implementation of {@link ModeSetter} that does not set any permissions or preserve mtime and atime. */
public class DefaultModeSetter implements ModeSetter {

    public void setLastAccessedTime(File f, long t) throws IOException {
        // can't do ntn
    }

    public void setLastModifiedTime(File f, long t) throws IOException {
        // f.setLastModified(t * 1000);
    }

    public void setPermissions(File f, int perms) throws IOException {
        // TODO: set user's rwx permissions; can't do anything about group and world
    }

    public boolean preservesTimes() {
        return false;
    }

}