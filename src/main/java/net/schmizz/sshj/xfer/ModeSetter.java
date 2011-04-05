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
package net.schmizz.sshj.xfer;

import java.io.File;
import java.io.IOException;

/** An interface for setting file permissions and times. */
public interface ModeSetter {

    /**
     * Set the last access time for {@code f}.
     *
     * @param f the file
     * @param t time in seconds since Unix epoch
     *
     * @throws IOException
     */
    void setLastAccessedTime(File f, long t)
            throws IOException;

    /**
     * Set the last modified time for {@code f}.
     *
     * @param f the file
     * @param t time in seconds since Unix epoch
     *
     * @throws IOException
     */
    void setLastModifiedTime(File f, long t)
            throws IOException;

    /**
     * Set the permissions for {@code f}.
     *
     * @param f     the file
     * @param perms permissions in octal format, e.g. "644"
     *
     * @throws IOException
     */
    void setPermissions(File f, int perms)
            throws IOException;

    /** @return whether this implementation is interested in preserving mtime and atime. */
    boolean preservesTimes();

}
