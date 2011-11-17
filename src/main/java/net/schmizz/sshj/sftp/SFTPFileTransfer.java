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
package net.schmizz.sshj.sftp;

import net.schmizz.sshj.common.StreamCopier;
import net.schmizz.sshj.sftp.Response.StatusCode;
import net.schmizz.sshj.xfer.AbstractFileTransfer;
import net.schmizz.sshj.xfer.FileSystemFile;
import net.schmizz.sshj.xfer.FileTransfer;
import net.schmizz.sshj.xfer.LocalDestFile;
import net.schmizz.sshj.xfer.LocalFileFilter;
import net.schmizz.sshj.xfer.LocalSourceFile;
import net.schmizz.sshj.xfer.TransferListener;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;

public class SFTPFileTransfer
        extends AbstractFileTransfer
        implements FileTransfer {

    private final SFTPEngine engine;

    private volatile LocalFileFilter uploadFilter;
    private volatile RemoteResourceFilter downloadFilter;

    public SFTPFileTransfer(SFTPEngine engine) {
        this.engine = engine;
    }

    /**
     * Equivalent to calling upload(source, dest, true).
     */
    @Override
    public void upload(String source, String dest)
            throws IOException {
        upload(source, dest, true);
    }

    /**
     * Uploads the file at the given path to dest. If setRemoteFileAttributes
     * is true, this will send an additional request to set the remote file's
     * attributes to those of the file at the given path.
     */
    public void upload(String source, String dest, boolean setRemoteFileAttributes)
            throws IOException {
        new Uploader().upload(new FileSystemFile(source), dest, setRemoteFileAttributes);
    }

    @Override
    public void download(String source, String dest)
            throws IOException {
        download(source, new FileSystemFile(dest));
    }

    /**
     * Equivalent to calling upload(localFile, remotePath, true).
     */
    @Override
    public void upload(LocalSourceFile localFile, String remotePath)
            throws IOException {
        upload(localFile, remotePath, true);
    }

    /**
     * Uploads the file the given file to dest. If setRemoteFileAttributes is 
     * true, this will send an additional request to set the remote file's
     * attributes to those of the given file.
     */
    public void upload(LocalSourceFile localFile, String remotePath, boolean setRemoteFileAttributes)
        throws IOException {
        new Uploader().upload(localFile, remotePath, setRemoteFileAttributes);        
    }

    @Override
    public void download(String source, LocalDestFile dest)
            throws IOException {
        final PathComponents pathComponents = engine.getPathHelper().getComponents(source);
        final FileAttributes attributes = engine.stat(source);
        new Downloader().download(new RemoteResourceInfo(pathComponents, attributes), dest);
    }

    public void setUploadFilter(LocalFileFilter uploadFilter) {
        this.uploadFilter = uploadFilter;
    }

    public void setDownloadFilter(RemoteResourceFilter downloadFilter) {
        this.downloadFilter = downloadFilter;
    }

    public LocalFileFilter getUploadFilter() {
        return uploadFilter;
    }

    public RemoteResourceFilter getDownloadFilter() {
        return downloadFilter;
    }

    private class Downloader {

        private final TransferListener listener = getTransferListener();

        private void download(final RemoteResourceInfo remote, final LocalDestFile local)
                throws IOException {
            final LocalDestFile adjustedFile;
            switch (remote.getAttributes().getType()) {
                case DIRECTORY:
                    listener.startedDir(remote.getName());
                    adjustedFile = downloadDir(remote, local);
                    listener.finishedDir();
                    break;
                case UNKNOWN:
                    log.warn("Server did not supply information about the type of file at `{}` " +
                                     "-- assuming it is a regular file!", remote.getPath());
                case REGULAR:
                    listener.startedFile(remote.getName(), remote.getAttributes().getSize());
                    adjustedFile = downloadFile(remote, local);
                    listener.finishedFile();
                    break;
                default:
                    throw new IOException(remote + " is not a regular file or directory");
            }
            copyAttributes(remote, adjustedFile);

        }

        private LocalDestFile downloadDir(final RemoteResourceInfo remote, final LocalDestFile local)
                throws IOException {
            final LocalDestFile adjusted = local.getTargetDirectory(remote.getName());
            final RemoteDirectory rd = engine.openDir(remote.getPath());
            try {
                for (RemoteResourceInfo rri : rd.scan(getDownloadFilter()))
                    download(rri, adjusted.getChild(rri.getName()));
            } finally {
                rd.close();
            }
            return adjusted;
        }

        private LocalDestFile downloadFile(final RemoteResourceInfo remote, final LocalDestFile local)
                throws IOException {
            final LocalDestFile adjusted = local.getTargetFile(remote.getName());
            final RemoteFile rf = engine.open(remote.getPath());
            try {
                final OutputStream os = adjusted.getOutputStream();
                try {
                    new StreamCopier(rf.getInputStream(), os)
                            .bufSize(engine.getSubsystem().getLocalMaxPacketSize())
                            .keepFlushing(false)
                            .listener(listener)
                            .copy();
                } finally {
                    os.close();
                }
            } finally {
                rf.close();
            }
            return adjusted;
        }

        private void copyAttributes(final RemoteResourceInfo remote, final LocalDestFile local)
                throws IOException {
            final FileAttributes attrs = remote.getAttributes();
            local.setPermissions(attrs.getMode().getPermissionsMask());
            if (attrs.has(FileAttributes.Flag.ACMODTIME)) {
                local.setLastAccessedTime(attrs.getAtime());
                local.setLastModifiedTime(attrs.getMtime());
            }
        }

    }

    private class Uploader {

        private final TransferListener listener = getTransferListener();

        private void upload(LocalSourceFile local, String remote, boolean setRemoteFileAttributes)
                throws IOException {
            final String adjustedPath;
            if (local.isDirectory()) {
                listener.startedDir(local.getName());
                adjustedPath = uploadDir(local, remote, setRemoteFileAttributes);
                listener.finishedDir();
            } else if (local.isFile()) {
                listener.startedFile(local.getName(), local.getLength());
                adjustedPath = uploadFile(local, remote);
                listener.finishedFile();
            } else
                throw new IOException(local + " is not a file or directory");

            if (setRemoteFileAttributes) {
                engine.setAttributes(adjustedPath, getAttributes(local));
            }
        }

        private String uploadDir(LocalSourceFile local, String remote, boolean setRemoteFileAttributes)
                throws IOException {
            final String adjusted = prepareDir(local, remote);
            for (LocalSourceFile f : local.getChildren(getUploadFilter()))
                upload(f, adjusted, setRemoteFileAttributes);
            return adjusted;
        }

        private String uploadFile(LocalSourceFile local, String remote)
                throws IOException {
            final String adjusted = prepareFile(local, remote);
            final RemoteFile rf = engine.open(adjusted, EnumSet.of(OpenMode.WRITE,
                                                                   OpenMode.CREAT,
                                                                   OpenMode.TRUNC));
            try {
                final InputStream fis = local.getInputStream();
                try {
                    new StreamCopier(fis, rf.getOutputStream())
                            .bufSize(engine.getSubsystem().getRemoteMaxPacketSize() - rf.getOutgoingPacketOverhead())
                            .keepFlushing(false)
                            .listener(listener)
                            .copy();
                } finally {
                    fis.close();
                }
            } finally {
                rf.close();
            }
            return adjusted;
        }

        private String prepareDir(LocalSourceFile local, String remote)
                throws IOException {
            final FileAttributes attrs;
            try {
                attrs = engine.stat(remote);
            } catch (SFTPException e) {
                if (e.getStatusCode() == StatusCode.NO_SUCH_FILE) {
                    log.debug("probeDir: {} does not exist, creating", remote);
                    engine.makeDir(remote);
                    return remote;
                } else
                    throw e;
            }

            if (attrs.getMode().getType() == FileMode.Type.DIRECTORY)
                if (engine.getPathHelper().getComponents(remote).getName().equals(local.getName())) {
                    log.debug("probeDir: {} already exists", remote);
                    return remote;
                } else {
                    log.debug("probeDir: {} already exists, path adjusted for {}", remote, local.getName());
                    return prepareDir(local, engine.getPathHelper().adjustForParent(remote, local.getName()));
                }
            else
                throw new IOException(attrs.getMode().getType() + " file already exists at " + remote);
        }

        private String prepareFile(LocalSourceFile local, String remote)
                throws IOException {
            final FileAttributes attrs;
            try {
                attrs = engine.stat(remote);
            } catch (SFTPException e) {
                if (e.getStatusCode() == StatusCode.NO_SUCH_FILE) {
                    log.debug("probeFile: {} does not exist", remote);
                    return remote;
                } else
                    throw e;
            }
            if (attrs.getMode().getType() == FileMode.Type.DIRECTORY) {
                log.debug("probeFile: {} was directory, path adjusted for {}", remote, local.getName());
                remote = engine.getPathHelper().adjustForParent(remote, local.getName());
                return remote;
            } else {
                log.debug("probeFile: {} is a {} file that will be replaced", remote, attrs.getMode().getType());
                return remote;
            }
        }

        private FileAttributes getAttributes(LocalSourceFile local)
                throws IOException {
            final FileAttributes.Builder builder = new FileAttributes.Builder().withPermissions(local.getPermissions());
            if (local.providesAtimeMtime())
                builder.withAtimeMtime(local.getLastAccessTime(), local.getLastModifiedTime());
            return builder.build();
        }

    }

}
