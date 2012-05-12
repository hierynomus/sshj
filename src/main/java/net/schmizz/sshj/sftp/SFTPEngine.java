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
package net.schmizz.sshj.sftp;

import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.connection.channel.direct.Session.Subsystem;
import net.schmizz.sshj.connection.channel.direct.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class SFTPEngine
        implements Requester, Closeable {

    public static final int MAX_SUPPORTED_VERSION = 3;
    public static final int DEFAULT_TIMEOUT = 30;

    /** Logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());

    protected volatile int timeout = DEFAULT_TIMEOUT;

    protected final PathHelper pathHelper;

    protected final Subsystem sub;
    protected final PacketReader reader;
    protected final OutputStream out;

    protected long reqID;
    protected int operativeVersion;
    protected final Map<String, String> serverExtensions = new HashMap<String, String>();

    public SFTPEngine(SessionFactory ssh)
            throws SSHException {
        this(ssh, PathHelper.DEFAULT_PATH_SEPARATOR);
    }

    public SFTPEngine(SessionFactory ssh, String pathSep)
            throws SSHException {
        sub = ssh.startSession().startSubsystem("sftp");
        out = sub.getOutputStream();
        reader = new PacketReader(this);
        pathHelper = new PathHelper(new PathHelper.Canonicalizer() {
            @Override
            public String canonicalize(String path)
                    throws IOException {
                return SFTPEngine.this.canonicalize(path);
            }
        }, pathSep);
    }

    public SFTPEngine init()
            throws IOException {
        transmit(new SFTPPacket<Request>(PacketType.INIT).putUInt32(MAX_SUPPORTED_VERSION));

        final SFTPPacket<Response> response = reader.readPacket();

        final PacketType type = response.readType();
        if (type != PacketType.VERSION)
            throw new SFTPException("Expected INIT packet, received: " + type);

        operativeVersion = response.readUInt32AsInt();
        log.info("Server version {}", operativeVersion);
        if (MAX_SUPPORTED_VERSION < operativeVersion)
            throw new SFTPException("Server reported incompatible protocol version: " + operativeVersion);

        while (response.available() > 0)
            serverExtensions.put(response.readString(), response.readString());

        // Start reader thread
        reader.start();
        return this;
    }

    public Subsystem getSubsystem() {
        return sub;
    }

    public int getOperativeProtocolVersion() {
        return operativeVersion;
    }

    public Request newExtendedRequest(String reqName) {
        return newRequest(PacketType.EXTENDED).putString(reqName);
    }

    @Override
    public PathHelper getPathHelper() {
        return pathHelper;
    }

    @Override
    public synchronized Request newRequest(PacketType type) {
        return new Request(type, reqID = reqID + 1 & 0xffffffffL);
    }

    @Override
    public Response doRequest(Request req)
            throws IOException {
        reader.expectResponseTo(req);
        log.debug("Sending {}", req);
        transmit(req);
        return req.getResponsePromise().retrieve(timeout, TimeUnit.SECONDS);
    }

    public RemoteFile open(String path, Set<OpenMode> modes, FileAttributes fa)
            throws IOException {
        final String handle = doRequest(
                newRequest(PacketType.OPEN).putString(path).putUInt32(OpenMode.toMask(modes)).putFileAttributes(fa)
        ).ensurePacketTypeIs(PacketType.HANDLE).readString();
        return new RemoteFile(this, path, handle);
    }

    public RemoteFile open(String filename, Set<OpenMode> modes)
            throws IOException {
        return open(filename, modes, FileAttributes.EMPTY);
    }

    public RemoteFile open(String filename)
            throws IOException {
        return open(filename, EnumSet.of(OpenMode.READ));
    }

    public RemoteDirectory openDir(String path)
            throws IOException {
        final String handle = doRequest(
                newRequest(PacketType.OPENDIR).putString(path)
        ).ensurePacketTypeIs(PacketType.HANDLE).readString();
        return new RemoteDirectory(this, path, handle);
    }

    public void setAttributes(String path, FileAttributes attrs)
            throws IOException {
        doRequest(
                newRequest(PacketType.SETSTAT).putString(path).putFileAttributes(attrs)
        ).ensureStatusPacketIsOK();
    }

    public String readLink(String path)
            throws IOException {
        if (operativeVersion < 3)
            throw new SFTPException("READLINK is not supported in SFTPv" + operativeVersion);
        return readSingleName(
                doRequest(
                        newRequest(PacketType.READLINK).putString(path)
                ));
    }

    public void makeDir(String path, FileAttributes attrs)
            throws IOException {
        doRequest(newRequest(PacketType.MKDIR).putString(path).putFileAttributes(attrs)).ensureStatusPacketIsOK();
    }

    public void makeDir(String path)
            throws IOException {
        makeDir(path, FileAttributes.EMPTY);
    }

    public void symlink(String linkpath, String targetpath)
            throws IOException {
        if (operativeVersion < 3)
            throw new SFTPException("SYMLINK is not supported in SFTPv" + operativeVersion);
        doRequest(
                newRequest(PacketType.SYMLINK).putString(linkpath).putString(targetpath)
        ).ensureStatusPacketIsOK();
    }

    public void remove(String filename)
            throws IOException {
        doRequest(
                newRequest(PacketType.REMOVE).putString(filename)
        ).ensureStatusPacketIsOK();
    }

    public void removeDir(String path)
            throws IOException {
        doRequest(
                newRequest(PacketType.RMDIR).putString(path)
        ).ensureStatusIs(Response.StatusCode.OK);
    }

    public FileAttributes stat(String path)
            throws IOException {
        return stat(PacketType.STAT, path);
    }

    public FileAttributes lstat(String path)
            throws IOException {
        return stat(PacketType.LSTAT, path);
    }

    public void rename(String oldPath, String newPath)
            throws IOException {
        if (operativeVersion < 1)
            throw new SFTPException("RENAME is not supported in SFTPv" + operativeVersion);
        doRequest(
                newRequest(PacketType.RENAME).putString(oldPath).putString(newPath)
        ).ensureStatusPacketIsOK();
    }

    public String canonicalize(String path)
            throws IOException {
        return readSingleName(
                doRequest(
                        newRequest(PacketType.REALPATH).putString(path)
                ));
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getTimeout() {
        return timeout;
    }

    @Override
    public void close()
            throws IOException {
        sub.close();
    }

    protected FileAttributes stat(PacketType pt, String path)
            throws IOException {
        return doRequest(newRequest(pt).putString(path))
                .ensurePacketTypeIs(PacketType.ATTRS)
                .readFileAttributes();
    }

    protected static String readSingleName(Response res)
            throws IOException {
        res.ensurePacketTypeIs(PacketType.NAME);
        if (res.readUInt32AsInt() == 1)
            return res.readString();
        else
            throw new SFTPException("Unexpected data in " + res.getType() + " packet");
    }

    protected synchronized void transmit(SFTPPacket<Request> payload)
            throws IOException {
        final int len = payload.available();
        out.write((len >>> 24) & 0xff);
        out.write((len >>> 16) & 0xff);
        out.write((len >>> 8) & 0xff);
        out.write(len & 0xff);
        out.write(payload.array(), payload.rpos(), len);
        out.flush();
    }

}
