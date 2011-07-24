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

public interface LocalSourceFile {

    String getName();

    long getLength();

    InputStream getInputStream()
            throws IOException;

    /**
     * Returns the permissions for the underlying file
     *
     * @return permissions e.g. 0644
     *
     * @throws IOException
     */
    int getPermissions()
            throws IOException;

    boolean isFile();

    boolean isDirectory();

    Iterable<? extends LocalSourceFile> getChildren(LocalFileFilter filter)
            throws IOException;

    boolean providesAtimeMtime();

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

}
