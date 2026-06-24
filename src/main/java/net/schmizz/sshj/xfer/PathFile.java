/*
 * Copyright (C)2009 - SSHJ Contributors
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
import java.io.UncheckedIOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A file implementation using {@link Path} (NIO API).
 */
public class PathFile
        implements LocalSourceFile, LocalDestFile {

    private final Path path;

    public PathFile(String path) {
        this(Paths.get(path));
    }

    public PathFile(Path path) {
        this.path = path;
    }

    public Path getPath() {
        return path;
    }

    @Override
    public String getName() {
        return path.getFileName().toString();
    }

    @Override
    public boolean isFile() {
        return Files.isRegularFile(path);
    }

    @Override
    public boolean isDirectory() {
        return Files.isDirectory(path);
    }

    public boolean exists() {
        return Files.exists(path);
    }

    @Override
    public long getLength() {
        try {
            return Files.size(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public InputStream getInputStream()
            throws IOException {
        return Files.newInputStream(path);
    }

    @Override
    public OutputStream getOutputStream()
            throws IOException {
        return Files.newOutputStream(path);
    }

    @Override
    public OutputStream getOutputStream(boolean append)
            throws IOException {
        return Files.newOutputStream(path, StandardOpenOption.APPEND);
    }

    @Override
    public Iterable<PathFile> getChildren(final LocalFileFilter filter)
            throws IOException {
        try (Stream<Path> pathStream = Files.list(path)) {
            return pathStream
                    .map(PathFile::new)
                    .filter(p -> filter == null || filter.accept(p))
                    .collect(Collectors.toList());
        }
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
        return Files.getLastModifiedTime(path).to(TimeUnit.SECONDS);
    }

    @Override
    public int getPermissions()
            throws IOException {
        Set<FilePermission> permissions = Files.getPosixFilePermissions(path).stream().map(FilePermission::of).collect(Collectors.toSet());
        return FilePermission.toMask(permissions);
    }

    @Override
    public void setLastAccessedTime(long t)
            throws IOException {
        // ...
    }

    @Override
    public void setLastModifiedTime(long t)
            throws IOException {
        Files.setLastModifiedTime(path, FileTime.from(t, TimeUnit.SECONDS));
    }

    @Override
    public void setPermissions(int perms)
            throws IOException {
        Set<FilePermission> permissions = FilePermission.fromMask(perms);
        Set<PosixFilePermission> posix = Arrays.stream(PosixFilePermission.values())
                .filter(p -> permissions.contains(FilePermission.of(p)))
                .collect(Collectors.toSet());
        Files.setPosixFilePermissions(path, posix);
    }

    @Override
    public PathFile getChild(String name) {
        Path resolved = path.resolve(name).normalize();
        if (!resolved.startsWith(path)) {
            throw new IllegalArgumentException("Cannot traverse higher than " + path + " to get child " + name);
        }
        return new PathFile(resolved);
    }

    @Override
    public PathFile getTargetFile(String filename)
            throws IOException {
        PathFile f = this;

        if (f.isDirectory()) {
            f = f.getChild(filename);
        }

        try {
            Files.createFile(f.getPath());
        } catch (FileAlreadyExistsException ignore) {
        }

        return f;
    }

    @Override
    public PathFile getTargetDirectory(String dirname)
            throws IOException {
        PathFile f = this;

        if (f.exists()) {
            if (f.isDirectory()) {
                if (!f.getName().equals(dirname)) {
                    f = f.getChild(dirname);
                }
            } else {
                throw new IOException(f + " - already exists as a file; directory required");
            }
        }

        Files.createDirectories(f.getPath());

        return f;
    }

    @Override
    public boolean equals(Object other) {
        return (other instanceof PathFile)
                && path.equals(((PathFile) other).path);
    }

    @Override
    public int hashCode() {
        return path.hashCode();
    }

    @Override
    public String toString() {
        return path.toString();
    }

}
