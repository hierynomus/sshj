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
package net.schmizz.sshj.xfer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public abstract class InMemorySourceFile
        implements LocalSourceFile {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public boolean isFile() {
        return true;
    }

    @Override
    public boolean isDirectory() {
        return false;
    }

    @Override
    public int getPermissions()
            throws IOException {
        return 0644;
    }

    @Override
    public boolean providesAtimeMtime() {
        return false;
    }

    @Override
    public long getLastAccessTime()
            throws IOException {
        throw new AssertionError("Unimplemented");
    }

    @Override
    public long getLastModifiedTime()
            throws IOException {
        throw new AssertionError("Unimplemented");
    }

    @Override
    public Iterable<? extends LocalSourceFile> getChildren(LocalFileFilter filter)
            throws IOException {
        throw new AssertionError("Unimplemented");
    }

}
