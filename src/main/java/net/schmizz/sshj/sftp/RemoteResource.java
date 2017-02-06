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

import org.slf4j.Logger;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

public abstract class RemoteResource
        implements Closeable {

    /** Logger */
    protected final Logger log;

    protected final SFTPEngine requester;
    protected final String path;
    protected final byte[] handle;

    protected RemoteResource(SFTPEngine requester, String path, byte[] handle) {
        this.requester = requester;
        log = requester.getLoggerFactory().getLogger(getClass());
        this.path = path;
        this.handle = handle;
    }

    public String getPath() {
        return path;
    }

    protected Request newRequest(PacketType type) {
        return requester.newRequest(type).putString(handle);
    }

    @Override
    public void close()
            throws IOException {
        log.debug("Closing `{}`", this);
        requester.request(newRequest(PacketType.CLOSE))
                .retrieve(requester.getTimeoutMs(), TimeUnit.MILLISECONDS)
                .ensureStatusPacketIsOK();
    }

    @Override
    public String toString() {
        return "RemoteResource{" + path + "}";
    }

}
