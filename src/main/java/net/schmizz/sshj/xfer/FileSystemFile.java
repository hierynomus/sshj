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

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class FileSystemFile
        implements LocalSourceFile, LocalDestFile {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final File file;

    public FileSystemFile(String path) {
        this(new File(path));
    }

    public FileSystemFile(File file) {
        this.file = file;
    }

    public File getFile() {
        return file;
    }

    @Override
    public String getName() {
        return file.getName();
    }

    @Override
    public boolean isFile() {
        return file.isFile();
    }

    @Override
    public boolean isDirectory() {
        return file.isDirectory();
    }

    @Override
    public long getLength() {
        return file.length();
    }

    @Override
    public InputStream getInputStream()
            throws IOException {
        return new FileInputStream(file);
    }

    @Override
    public OutputStream getOutputStream()
            throws IOException {
        return new FileOutputStream(file);
    }

    @Override
    public Iterable<FileSystemFile> getChildren(final LocalFileFilter filter)
            throws IOException {
        File[] childFiles = filter == null ? file.listFiles() : file.listFiles(new FileFilter() {
            @Override
            public boolean accept(File file) {
                return filter.accept(new FileSystemFile(file));
            }
        });

        if (childFiles == null)
            throw new IOException("Error listing files in directory: " + this);

        final List<FileSystemFile> children = new ArrayList<FileSystemFile>();
        for (File f : childFiles) {
            children.add(new FileSystemFile(f));
        }
        return children;
    }

    @Override
    public boolean providesAtimeMtime() {
        return true;
    }

    @Override
    public long getLastAccessTime()
            throws IOException {
        return System.currentTimeMillis() / 1000;
    }

    @Override
    public long getLastModifiedTime()
            throws IOException {
        return file.lastModified() / 1000;
    }

    @Override
    public int getPermissions()
            throws IOException {
        if (isDirectory())
            return 0755;
        else if (isFile())
            return 0644;
        else
            throw new IOException("Unsupported file type");
    }

    @Override
    public void setLastAccessedTime(long t)
            throws IOException {
        // ...
    }

    @Override
    public void setLastModifiedTime(long t)
            throws IOException {
        if (!file.setLastModified(t * 1000))
            log.warn("Could not set last modified time for {} to {}", file, t);
    }

    @Override
    public void setPermissions(int perms)
            throws IOException {
        final boolean r = file.setReadable(FilePermission.USR_R.isIn(perms),
                                           !(FilePermission.OTH_R.isIn(perms) || FilePermission.GRP_R.isIn(perms)));
        final boolean w = file.setWritable(FilePermission.USR_W.isIn(perms),
                                           !(FilePermission.OTH_W.isIn(perms) || FilePermission.GRP_W.isIn(perms)));
        final boolean x = file.setExecutable(FilePermission.USR_X.isIn(perms),
                                             !(FilePermission.OTH_X.isIn(perms) || FilePermission.GRP_X.isIn(perms)));
        if (!(r && w && x))
            log.warn("Could not set permissions for {} to {}", file, Integer.toString(perms, 16));
    }

    @Override
    public FileSystemFile getChild(String name) {
        return new FileSystemFile(new File(file, name));
    }

    @Override
    public FileSystemFile getTargetFile(String filename)
            throws IOException {
        FileSystemFile f = this;

        if (f.isDirectory())
            f = f.getChild(filename);

        if (!f.getFile().exists()) {
            if (!f.getFile().createNewFile())
                throw new IOException("Could not create: " + file);
        } else if (f.isDirectory())
            throw new IOException("A directory by the same name already exists: " + f);

        return f;
    }

    @Override
    public FileSystemFile getTargetDirectory(String dirname)
            throws IOException {
        FileSystemFile f = this;

        if (f.getFile().exists())
            if (f.isDirectory()) {
                if (!f.getName().equals(dirname))
                    f = f.getChild(dirname);
            } else
                throw new IOException(f + " - already exists as a file; directory required");

        if (!f.getFile().exists() && !f.getFile().mkdir())
            throw new IOException("Failed to create directory: " + f);

        return f;
    }

    @Override
    public boolean equals(Object other) {
        return (other instanceof FileSystemFile)
                && file.equals(((FileSystemFile) other).file);
    }

    @Override
    public int hashCode() {
        return file.hashCode();
    }

    @Override
    public String toString() {
        return file.toString();
    }

}
