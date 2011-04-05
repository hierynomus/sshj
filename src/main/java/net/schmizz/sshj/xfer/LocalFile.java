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
import java.io.InputStream;
import java.io.OutputStream;

// TODO Document all methods properly

public interface LocalFile {

    String getName();

	boolean isFile();

    boolean isDirectory();

	long length();

	InputStream getInputStream() throws IOException;

    OutputStream getOutputStream() throws IOException;

	Iterable<? extends LocalFile> getChildren() throws IOException;

    Iterable<? extends LocalFile> getChildren(LocalFileFilter filter) throws IOException;

    /**
     * Returns last access time for the underlying file.
     *
     * @return time in seconds since Unix epoch
     *
     * @throws IOException
     */
    long getLastAccessTime()
            throws IOException;

    /**
     * Returns last access time for the underlying file.
     *
     * @return time in seconds since Unix epoch
     *
     * @throws IOException
     */
    long getLastModifiedTime()
            throws IOException;

    /**
     * Returns the permissions for the underlying file
     *
     * @return permissions in octal format, e.g. 0644
     *
     * @throws IOException
     */
    int getPermissions()
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
     * @param f the file
     * @param t time in seconds since Unix epoch
     *
     * @throws IOException
     */
    void setLastModifiedTime(long t)
            throws IOException;

    /**
     * Set the permissions for the underlying file.
     *
     * @param f     the file
     * @param perms permissions in octal format, e.g. 0644
     *
     * @throws IOException
     */
    void setPermissions(int perms)
            throws IOException;

    /** @return whether this implementation is interested in preserving mtime and atime. */
    boolean preservesTimes();

    /** @return A child file of this directory having {@code name} as filename */
    LocalFile getChild(String name);

    LocalFile getTargetFile(String filename) throws IOException;

    LocalFile getTargetDirectory(String dirname) throws IOException;

}