/*
 * Copyright 2011 sshj contributors
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

import java.io.IOException;
import java.io.OutputStream;

public interface LocalDestFile {

    OutputStream getOutputStream()
            throws IOException;

    /** @return A child file/directory of this directory with given {@code name}. */
    LocalDestFile getChild(String name);

    /**
     * Allows caller to express intent that caller expects to write to file with {@code filename}. Based on this
     * information, an implementation may return an alternate file to write to, which should be respected by the
     * caller.
     */
    LocalDestFile getTargetFile(String filename)
            throws IOException;

    /**
     * Allows caller to express intent that caller expects to write to directory with {@code dirname}. Based on this
     * information, an implementation may return an alternate directory to write to, which should be respected by the
     * caller.
     */
    LocalDestFile getTargetDirectory(String dirname)
            throws IOException;

    /**
     * Set the permissions for the underlying file.
     *
     * @param perms permissions e.g. 0644
     *
     * @throws IOException
     */
    void setPermissions(int perms)
            throws IOException;

    /**
     * Set the last access time for the underlying file.
     *
     * @param t time in seconds since Unix epoch
     *
     * @throws IOException
     */
    void setLastAccessedTime(long t)
            throws IOException;

    /**
     * Set the last modified time for the underlying file.
     *
     * @param t time in seconds since Unix epoch
     *
     * @throws IOException
     */
    void setLastModifiedTime(long t)
            throws IOException;

}
