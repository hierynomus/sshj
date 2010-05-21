/*
 * Copyright 2010 Shikhar Bhushan
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
import net.schmizz.sshj.xfer.FileTransfer;
import net.schmizz.sshj.xfer.FileTransferUtil;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.EnumSet;

public class SFTPFileTransfer
        extends AbstractFileTransfer
        implements FileTransfer {

    private final SFTPEngine sftp;
    private final PathHelper pathHelper;

    private volatile FileFilter uploadFilter = defaultLocalFilter;
    private volatile RemoteResourceFilter downloadFilter = defaultRemoteFilter;

    private static final FileFilter defaultLocalFilter = new FileFilter() {
        @Override
        public boolean accept(File pathName) {
            return true;
        }
    };

    private static final RemoteResourceFilter defaultRemoteFilter = new RemoteResourceFilter() {
        @Override
        public boolean accept(RemoteResourceInfo resource) {
            return true;
        }
    };

    public SFTPFileTransfer(SFTPEngine sftp) {
        this.sftp = sftp;
        this.pathHelper = new PathHelper(sftp);
    }

    @Override
    public void upload(String source, String dest)
            throws IOException {
        new Uploader().upload(new File(source), dest);
    }

    @Override
    public void download(String source, String dest)
            throws IOException {
        final PathComponents pathComponents = pathHelper.getComponents(source);
        final FileAttributes attributes = sftp.stat(source);
        new Downloader().download(new RemoteResourceInfo(pathComponents, attributes), new File(dest));
    }

    public void setUploadFilter(FileFilter uploadFilter) {
        this.uploadFilter = (this.uploadFilter == null) ? defaultLocalFilter : uploadFilter;
    }

    public void setDownloadFilter(RemoteResourceFilter downloadFilter) {
        this.downloadFilter = (this.downloadFilter == null) ? defaultRemoteFilter : downloadFilter;
    }

    public FileFilter getUploadFilter() {
        return uploadFilter;
    }

    public RemoteResourceFilter getDownloadFilter() {
        return downloadFilter;
    }

    private class Downloader {

        private void download(final RemoteResourceInfo remote, final File local)
                throws IOException {
            log.info("Downloading [{}] to [{}]", remote, local);
            switch (remote.getAttributes().getType()) {
                case DIRECTORY:
                    downloadDir(remote, local);
                    break;
                case UNKNOWN:
                    log.warn("Server did not supply information about the type of file at `{}` -- assuming it is a regular file!");
                case REGULAR:
                    downloadFile(remote, local);
                    break;
                default:
                    throw new IOException(remote + " is not a regular file or directory");
            }
        }

        private void downloadDir(final RemoteResourceInfo remote, final File local)
                throws IOException {
            final File adjusted = FileTransferUtil.getTargetDirectory(local, remote.getName());
            setAttributes(remote, adjusted);
            final RemoteDirectory rd = sftp.openDir(remote.getPath());
            try {
                for (RemoteResourceInfo rri : rd.scan(getDownloadFilter()))
                    download(rri, new File(adjusted.getPath(), rri.getName()));
            } finally {
                rd.close();
            }
        }

        private void downloadFile(final RemoteResourceInfo remote, final File local)
                throws IOException {
            final File adjusted = FileTransferUtil.getTargetFile(local, remote.getName());
            setAttributes(remote, adjusted);
            final RemoteFile rf = sftp.open(remote.getPath());
            try {
                final FileOutputStream fos = new FileOutputStream(adjusted);
                try {
                    StreamCopier.copy(rf.getInputStream(), fos, sftp.getSubsystem()
                            .getLocalMaxPacketSize(), false);
                } finally {
                    fos.close();
                }
            } finally {
                rf.close();
            }
        }

        private void setAttributes(final RemoteResourceInfo remote, final File local)
                throws IOException {
            final FileAttributes attrs = remote.getAttributes();
            getModeSetter().setPermissions(local, attrs.getMode().getPermissionsMask());
            if (getModeSetter().preservesTimes() && attrs.has(FileAttributes.Flag.ACMODTIME)) {
                getModeSetter().setLastAccessedTime(local, attrs.getAtime());
                getModeSetter().setLastModifiedTime(local, attrs.getMtime());
            }
        }

    }

    private class Uploader {

        private void upload(File local, String remote)
                throws IOException {
            log.info("Uploading [{}] to [{}]", local, remote);
            if (local.isDirectory())
                uploadDir(local, remote);
            else if (local.isFile())
                uploadFile(local, remote);
            else
                throw new IOException(local + " is not a file or directory");
        }

        private void uploadDir(File local, String remote)
                throws IOException {
            final String adjusted = prepareDir(local, remote);
            for (File f : local.listFiles(getUploadFilter()))
                upload(f, adjusted);
        }

        private void uploadFile(File local, String remote)
                throws IOException {
            final String adjusted = prepareFile(local, remote);
            final RemoteFile rf = sftp.open(adjusted, EnumSet.of(OpenMode.WRITE, OpenMode.CREAT, OpenMode.TRUNC),
                                            getAttributes(local));
            try {
                final FileInputStream fis = new FileInputStream(local);
                try {
                    StreamCopier.copy(fis, rf.getOutputStream(), sftp.getSubsystem().getRemoteMaxPacketSize()
                                                                 - rf.getOutgoingPacketOverhead(), false);
                } finally {
                    fis.close();
                }
            } finally {
                rf.close();
            }
        }

        private String prepareDir(File local, String remote)
                throws IOException {
            final FileAttributes attrs;
            try {
                attrs = sftp.stat(remote);
            } catch (SFTPException e) {
                if (e.getStatusCode() == StatusCode.NO_SUCH_FILE) {
                    log.debug("probeDir: {} does not exist, creating", remote);
                    sftp.makeDir(remote, getAttributes(local));
                    return remote;
                } else
                    throw e;
            }

            if (attrs.getMode().getType() == FileMode.Type.DIRECTORY)
                if (pathHelper.getComponents(remote).getName().equals(local.getName())) {
                    log.debug("probeDir: {} already exists", remote);
                    final FileAttributes localAttrs = getAttributes(local);
                    if (attrs.getMode().getMask() != localAttrs.getMode().getMask()
                        || (getModeGetter().preservesTimes()
                            && (attrs.getAtime() != attrs.getAtime() || attrs.getMtime() != localAttrs.getMtime())))
                        sftp.setAttributes(remote, localAttrs);
                    return remote;
                } else {
                    log.debug("probeDir: {} already exists, path adjusted for {}", remote, local.getName());
                    return prepareDir(local, PathComponents.adjustForParent(remote, local.getName()));
                }
            else
                throw new IOException(attrs.getMode().getType() + " file already exists at " + remote);
        }

        private String prepareFile(File local, String remote)
                throws IOException {
            final FileAttributes attrs;
            try {
                attrs = sftp.stat(remote);
            } catch (SFTPException e) {
                if (e.getStatusCode() == StatusCode.NO_SUCH_FILE) {
                    log.debug("probeFile: {} does not exist", remote);
                    return remote;
                } else
                    throw e;
            }
            if (attrs.getMode().getType() == FileMode.Type.DIRECTORY) {
                log.debug("probeFile: {} was directory, path adjusted for {}", remote, local.getName());
                remote = PathComponents.adjustForParent(remote, local.getName());
                return remote;
            } else {
                log.debug("probeFile: {} is a {} file that will be replaced", remote, attrs.getMode().getType());
                return remote;
            }
        }

        private FileAttributes getAttributes(File local)
                throws IOException {
            final FileAttributes.Builder builder = new FileAttributes.Builder()
                    .withPermissions(getModeGetter().getPermissions(local));
            if (getModeGetter().preservesTimes())
                builder.withAtimeMtime(getModeGetter().getLastAccessTime(local), getModeGetter().getLastModifiedTime(local));
            return builder.build();
        }

    }

}
