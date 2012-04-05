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

public abstract class InMemoryDestFile
        implements LocalDestFile {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public InMemoryDestFile getTargetFile(String filename)
            throws IOException {
        return this;
    }

    @Override
    public void setLastAccessedTime(long t)
            throws IOException {
        log.info("atime = {}", t);
    }

    @Override
    public void setLastModifiedTime(long t)
            throws IOException {
        log.info("mtime = {}", t);
    }

    @Override
    public void setPermissions(int perms)
            throws IOException {
        log.info("permissions = {}", Integer.toOctalString(perms));
    }

    @Override
    public LocalDestFile getTargetDirectory(String dirname)
            throws IOException {
        throw new AssertionError("Unimplemented");
    }

    @Override
    public LocalDestFile getChild(String name) {
        throw new AssertionError("Unimplemented");
    }

}
