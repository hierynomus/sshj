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

import net.schmizz.sshj.sftp.Response.StatusCode;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class RemoteDirectory
        extends RemoteResource {

    public RemoteDirectory(Requester requester, String path, String handle) {
        super(requester, path, handle);
    }

    public List<RemoteResourceInfo> scan(RemoteResourceFilter filter)
            throws IOException {
        List<RemoteResourceInfo> rri = new LinkedList<RemoteResourceInfo>();
        loop:
        for (; ; ) {
            Response res = requester.doRequest(newRequest(PacketType.READDIR));
            switch (res.getType()) {

                case NAME:
                    final int count = res.readUInt32AsInt();
                    for (int i = 0; i < count; i++) {
                        final String name = res.readString();
                        res.readString(); // long name - IGNORED - shdve never been in the protocol
                        final FileAttributes attrs = res.readFileAttributes();
                        final PathComponents comps = requester.getPathHelper().getComponents(path, name);
                        final RemoteResourceInfo inf = new RemoteResourceInfo(comps, attrs);
                        if (!(name.equals(".") || name.equals("..")) && (filter == null || filter.accept(inf)))
                            rri.add(inf);
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
