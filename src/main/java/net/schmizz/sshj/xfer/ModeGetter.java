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

/** An interface for retrieving information about file permissions and times. */
public interface ModeGetter {

    /**
     * Returns last access time for {@code f}.
     *
     * @param f the file
     *
     * @return time in seconds since Unix epoch
     *
     * @throws IOException
     */
    long getLastAccessTime(File f)
            throws IOException;

    /**
     * Returns last modified time for {@code f}.
     *
     * @param f the file
     *
     * @return time in seconds since Unix epoch
     *
     * @throws IOException
     */
    long getLastModifiedTime(File f)
            throws IOException;


    /**
     * Returns the permissions for {@code f}.
     *
     * @param f the file
     *
     * @return permissions in octal format, e.g. 0644
     *
     * @throws IOException
     */
    int getPermissions(File f)
            throws IOException;
    
    /**
     * Returns last access time for {@code f}.
     *
     * @param f the file
     *
     * @return time in seconds since Unix epoch
     *
     * @throws IOException
     */
    long getLastAccessTime(LocalFile f)
            throws IOException;

    /**
     * Returns last modified time for {@code f}.
     *
     * @param f the file
     *
     * @return time in seconds since Unix epoch
     *
     * @throws IOException
     */
    long getLastModifiedTime(LocalFile f)
            throws IOException;


    /**
     * Returns the permissions for {@code f}.
     *
     * @param f the file
     *
     * @return permissions in octal format, e.g. 0644
     *
     * @throws IOException
     */
    int getPermissions(LocalFile f)
            throws IOException;
    
    /** @return whether this implementation can provide mtime and atime information. */
    boolean preservesTimes();

}