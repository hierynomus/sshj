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
package net.schmizz.sshj.sftp;

import com.hierynomus.sshj.sftp.RemoteResourceSelector;
import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import net.schmizz.sshj.xfer.FilePermission;
import net.schmizz.sshj.xfer.LocalDestFile;
import net.schmizz.sshj.xfer.LocalSourceFile;
import org.slf4j.Logger;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;

import static com.hierynomus.sshj.sftp.RemoteResourceFilterConverter.selectorFrom;

public class SFTPClient
        implements Closeable {

    /** Logger */
    protected final Logger log;

    protected final SFTPEngine engine;
    protected final SFTPFileTransfer xfer;

    public SFTPClient(SFTPEngine engine) {
        this.engine = engine;
        log = engine.getLoggerFactory().getLogger(getClass());
        this.xfer = new SFTPFileTransfer(engine);
    }

    public SFTPClient(SessionFactory sessionFactory) throws IOException {
        this.engine = new SFTPEngine(sessionFactory);
        this.engine.init();
        log = engine.getLoggerFactory().getLogger(getClass());
        this.xfer = new SFTPFileTransfer(engine);
    }

    public SFTPEngine getSFTPEngine() {
        return engine;
    }

    public SFTPFileTransfer getFileTransfer() {
        return xfer;
    }

    public List<RemoteResourceInfo> ls(String path)
            throws IOException {
        return ls(path, RemoteResourceSelector.ALL);
    }

    public List<RemoteResourceInfo> ls(String path, RemoteResourceFilter filter)
            throws IOException {
        return ls(path, selectorFrom(filter));
    }

    public List<RemoteResourceInfo> ls(String path, RemoteResourceSelector selector)
            throws IOException {
        try (RemoteDirectory dir = engine.openDir(path)) {
            return dir.scan(selector == null ? RemoteResourceSelector.ALL : selector);
        }
    }

    public RemoteFile open(String filename, Set<OpenMode> mode, FileAttributes attrs)
            throws IOException {
        log.debug("Opening `{}`", filename);
        return engine.open(filename, mode, attrs);
    }

    public RemoteFile open(String filename, Set<OpenMode> mode)
            throws IOException {
        return open(filename, mode, FileAttributes.EMPTY);
    }

    public RemoteFile open(String filename)
            throws IOException {
        return open(filename, EnumSet.of(OpenMode.READ));
    }

    public void mkdir(String dirname)
            throws IOException {
        engine.makeDir(dirname);
    }

    public void mkdirs(String path)
            throws IOException {
        final Deque<String> dirsToMake = new LinkedList<String>();
        for (PathComponents current = engine.getPathHelper().getComponents(path); ;
             current = engine.getPathHelper().getComponents(current.getParent())) {
            final FileAttributes attrs = statExistence(current.getPath());
            if (attrs == null) {
                dirsToMake.push(current.getPath());
            } else if (attrs.getType() != FileMode.Type.DIRECTORY) {
                throw new SFTPException(current.getPath() + " exists but is not a directory");
            } else {
                break;
            }
        }
        while (!dirsToMake.isEmpty()) {
            mkdir(dirsToMake.pop());
        }
    }

    public FileAttributes statExistence(String path)
            throws IOException {
        try {
            return engine.stat(path);
        } catch (SFTPException sftpe) {
            if (sftpe.getStatusCode() == Response.StatusCode.NO_SUCH_FILE) {
                return null;
            } else {
                throw sftpe;
            }
        }
    }

    public void rename(String oldpath, String newpath) throws IOException {
        rename(oldpath, newpath, EnumSet.noneOf(RenameFlags.class));
    }

    public void rename(String oldpath, String newpath, Set<RenameFlags> renameFlags)
            throws IOException {
        engine.rename(oldpath, newpath, renameFlags);
    }

    public void rm(String filename)
            throws IOException {
        engine.remove(filename);
    }

    public void rmdir(String dirname)
            throws IOException {
        engine.removeDir(dirname);
    }

    /**
     * Removes {@code path} and, if it is a directory, everything beneath it (like {@code rm -r}).
     * <p>
     * SFTP has no recursive delete operation (in any protocol version), so this is done client-side with one
     * request per entry, which can be slow for large trees. It is not atomic: if an error occurs, the entries
     * removed so far stay removed and the exception is propagated.
     * <ul>
     *   <li>Symbolic links are removed, never followed, so their targets are left untouched.</li>
     *   <li>If {@code path} is a file or a symbolic link, only that file or link is removed.</li>
     *   <li>If {@code path} does not exist, an {@link SFTPException} is thrown (as for {@link #rmdir}).</li>
     *   <li>The root directory ({@code /}) and empty paths are rejected.</li>
     * </ul>
     *
     * @param path the file, link or directory to remove
     * @throws IOException on failure, e.g. missing path or insufficient permissions
     */
    public void rmdirs(String path)
            throws IOException {
        if (path == null || path.trim().isEmpty() || path.matches("/+")) {
            throw new IllegalArgumentException("Refusing to recursively remove `" + path + "`");
        }
        // lstat, so that a symlink to a directory is treated as a link and not followed
        if (lstat(path).getType() != FileMode.Type.DIRECTORY) {
            rm(path);
            return;
        }
        // Directories in discovery order: parents always precede their children.
        final List<String> dirs = new ArrayList<String>();
        final Deque<String> toScan = new ArrayDeque<String>();
        dirs.add(path);
        toScan.push(path);
        while (!toScan.isEmpty()) {
            // ls() reads the complete listing before we start removing anything from the directory
            for (RemoteResourceInfo entry : ls(toScan.pop())) {
                if (entry.isDirectory()) {
                    dirs.add(entry.getPath());
                    toScan.push(entry.getPath());
                } else {
                    log.debug("Removing `{}`", entry.getPath());
                    rm(entry.getPath());
                }
            }
        }
        // Children were discovered after their parents, so removing in reverse removes children first.
        for (int i = dirs.size() - 1; i >= 0; i--) {
            log.debug("Removing directory `{}`", dirs.get(i));
            rmdir(dirs.get(i));
        }
    }

    public void symlink(String linkpath, String targetpath)
            throws IOException {
        engine.symlink(linkpath, targetpath);
    }

    public int version() {
        return engine.getOperativeProtocolVersion();
    }

    public void setattr(String path, FileAttributes attrs)
            throws IOException {
        engine.setAttributes(path, attrs);
    }

    public int uid(String path)
            throws IOException {
        return stat(path).getUID();
    }

    public int gid(String path)
            throws IOException {
        return stat(path).getGID();
    }

    public long atime(String path)
            throws IOException {
        return stat(path).getAtime();
    }

    public long mtime(String path)
            throws IOException {
        return stat(path).getMtime();
    }

    public Set<FilePermission> perms(String path)
            throws IOException {
        return stat(path).getPermissions();
    }

    public FileMode mode(String path)
            throws IOException {
        return stat(path).getMode();
    }

    public FileMode.Type type(String path)
            throws IOException {
        return stat(path).getType();
    }

    public String readlink(String path)
            throws IOException {
        return engine.readLink(path);
    }

    public FileAttributes stat(String path)
            throws IOException {
        return engine.stat(path);
    }

    public FileAttributes lstat(String path)
            throws IOException {
        return engine.lstat(path);
    }

    public void chown(String path, int uid)
            throws IOException {
        setattr(path, new FileAttributes.Builder().withUIDGID(uid, gid(path)).build());
    }

    public void chmod(String path, int perms)
            throws IOException {
        setattr(path, new FileAttributes.Builder().withPermissions(perms).build());
    }

    public void chgrp(String path, int gid)
            throws IOException {
        setattr(path, new FileAttributes.Builder().withUIDGID(uid(path), gid).build());
    }

    public void truncate(String path, long size)
            throws IOException {
        setattr(path, new FileAttributes.Builder().withSize(size).build());
    }

    public String canonicalize(String path)
            throws IOException {
        return engine.canonicalize(path);
    }

    public long size(String path)
            throws IOException {
        return stat(path).getSize();
    }

    public void get(String source, String dest)
            throws IOException {
        xfer.download(source, dest);
    }

    public void get(String source, String dest, long byteOffset)
            throws IOException {
        xfer.download(source, dest, byteOffset);
    }

    public void put(String source, String dest)
            throws IOException {
        xfer.upload(source, dest);
    }

    public void put(String source, String dest, long byteOffset)
            throws IOException {
        xfer.upload(source, dest, byteOffset);
    }

    public void get(String source, LocalDestFile dest)
            throws IOException {
        xfer.download(source, dest);
    }

    public void get(String source, LocalDestFile dest, long byteOffset)
            throws IOException {
        xfer.download(source, dest, byteOffset);
    }

    public void put(LocalSourceFile source, String dest)
            throws IOException {
        xfer.upload(source, dest);
    }

    public void put(LocalSourceFile source, String dest, long byteOffset)
            throws IOException {
        xfer.upload(source, dest, byteOffset);
    }

    @Override
    public void close()
            throws IOException {
        engine.close();
    }

}
