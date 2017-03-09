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

import net.schmizz.sshj.sftp.Response.StatusCode;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class RemoteDirectory
        extends RemoteResource {

    public RemoteDirectory(SFTPEngine requester, String path, byte[] handle) {
        super(requester, path, handle);
    }

    public List<RemoteResourceInfo> scan(RemoteResourceFilter filter)
            throws IOException {
        List<RemoteResourceInfo> rri = new LinkedList<RemoteResourceInfo>();
        // TODO: Remove GOTO! 
        loop:
        for (; ; ) {
            final Response res = requester.request(newRequest(PacketType.READDIR))
                    .retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS);
            switch (res.getType()) {

                case NAME:
                    final int count = res.readUInt32AsInt();
                    for (int i = 0; i < count; i++) {
                        final String name = res.readString(requester.sub.getRemoteCharset());
                        res.readString(); // long name - IGNORED - shdve never been in the protocol
                        final FileAttributes attrs = res.readFileAttributes();
                        final PathComponents comps = requester.getPathHelper().getComponents(path, name);
                        final RemoteResourceInfo inf = new RemoteResourceInfo(comps, attrs);
                        if (!(".".equals(name) || "..".equals(name)) && (filter == null || filter.accept(inf))) {
                            rri.add(inf);
                        }
                    }
                    break;

                case STATUS:
                    res.ensureStatusIs(StatusCode.EOF);
                    break loop;

                default:
                    throw new SFTPException("Unexpected packet: " + res.getType());
            }
        }
        return rri;
    }

}
