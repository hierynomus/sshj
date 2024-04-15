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
import net.schmizz.sshj.sftp.Response.StatusCode;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.sshj.sftp.RemoteResourceFilterConverter.selectorFrom;

public class RemoteDirectory
        extends RemoteResource {

    public RemoteDirectory(SFTPEngine requester, String path, byte[] handle) {
        super(requester, path, handle);
    }

    public List<RemoteResourceInfo> scan(RemoteResourceFilter filter)
            throws IOException {
        return scan(selectorFrom(filter));
    }

    public List<RemoteResourceInfo> scan(RemoteResourceSelector selector)
            throws IOException {
        if (selector == null) {
            selector = RemoteResourceSelector.ALL;
        }

        List<RemoteResourceInfo> remoteResourceInfos = new LinkedList<>();

        while (true) {
            final Response response = requester.request(newRequest(PacketType.READDIR))
                    .retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS);

            switch (response.getType()) {
                case NAME:
                    final int count = response.readUInt32AsInt();
                    for (int i = 0; i < count; i++) {
                        final String name = response.readString(requester.sub.getRemoteCharset());
                        response.readString(); // long name - IGNORED - shdve never been in the protocol
                        final FileAttributes attrs = response.readFileAttributes();
                        final PathComponents comps = requester.getPathHelper().getComponents(path, name);
                        final RemoteResourceInfo inf = new RemoteResourceInfo(comps, attrs);

                        if (".".equals(name) || "..".equals(name)) {
                            continue;
                        }

                        final RemoteResourceSelector.Result selectionResult = selector.select(inf);
                        switch (selectionResult) {
                            case ACCEPT:
                                remoteResourceInfos.add(inf);
                                break;
                            case CONTINUE:
                                continue;
                            case BREAK:
                                return remoteResourceInfos;
                        }
                    }
                    break;

                case STATUS:
                    response.ensureStatusIs(StatusCode.EOF);
                    return remoteResourceInfos;

                default:
                    throw new SFTPException("Unexpected packet: " + response.getType());
            }
        }
    }
}
