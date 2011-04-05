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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class InMemoryDestFile
        implements LocalFile {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected final String filename;
    protected final OutputStream outStream;

    public InMemoryDestFile(String filename, OutputStream outStream) {
        this.filename = filename;
        this.outStream = outStream;
    }

    @Override
    public String getName() {
        return filename;
    }

    @Override
    public LocalFile getTargetFile(String filename)
            throws IOException {
        if (filename.equals(this.filename))
            return this;
        else
            throw new IOException("Filename mismatch");
    }

    @Override
    public boolean isFile() {
        return true;
    }

    @Override
    public boolean isDirectory() {
        return false;
    }

    @Override
    public OutputStream getOutputStream()
            throws IOException {
        return outStream;
    }

    // Everything else is unimplemented

    @Override
    public long length() {
        return 0;
    }

    @Override
    public InputStream getInputStream()
            throws IOException {
        return null;
    }

    @Override
    public Iterable<LocalFile> getChildren()
            throws IOException {
        return null;
    }

    @Override
    public Iterable<LocalFile> getChildren(LocalFileFilter filter)
            throws IOException {
        return null;
    }

    @Override
    public long getLastAccessTime()
            throws IOException {
        return 0;
    }

    @Override
    public long getLastModifiedTime()
            throws IOException {
        return 0;
    }

    @Override
    public int getPermissions()
            throws IOException {
        return 0;
    }

    @Override
    public void setLastAccessedTime(long t)
            throws IOException {
    }

    @Override
    public void setLastModifiedTime(long t)
            throws IOException {
    }

    @Override
    public void setPermissions(int perms)
            throws IOException {
    }

    @Override
    public boolean preservesTimes() {
        return false;
    }

    @Override
    public LocalFile getChild(String name) {
        return null;
    }

    @Override
    public LocalFile getTargetDirectory(String dirname) {
        return null;
    }

}
