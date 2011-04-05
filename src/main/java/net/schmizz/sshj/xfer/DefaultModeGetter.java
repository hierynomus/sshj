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

/**
 * Default implementation of {@link ModeGetter} that supplies file permissions as {@code "0644"}, directory permissions
 * as {@code "0755"}, and preserves timestamps. Note that there is no way of getting the last access time with Java file
 * API's so it is returned as the current system time.
 */
public class DefaultModeGetter
        implements ModeGetter {

    @Override
    public long getLastAccessTime(File f) {
        return System.currentTimeMillis() / 1000;
    }

    @Override
    public long getLastModifiedTime(File f) {
        return f.lastModified() / 1000;
    }

    @Override
    public int getPermissions(File f)
            throws IOException {
        if (f.isDirectory())
            return 0755;
        else if (f.isFile())
            return 0644;
        else
            throw new IOException("Unsupported file type: " + f);
    }
    
    @Override
    public long getLastAccessTime(LocalFile f) {
        return System.currentTimeMillis() / 1000;
    }

    @Override
    public long getLastModifiedTime(LocalFile f) {
        return f.lastModified() / 1000;
    }

    @Override
    public int getPermissions(LocalFile f)
            throws IOException {
        if (f.isDirectory())
            return 0755;
        else if (f.isFile())
            return 0644;
        else
            throw new IOException("Unsupported file type: " + f);
    }

    @Override
    public boolean preservesTimes() {
        return true;
    }

}
