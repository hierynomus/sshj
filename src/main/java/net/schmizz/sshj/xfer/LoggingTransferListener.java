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

import net.schmizz.sshj.common.LoggerFactory;
import net.schmizz.sshj.common.StreamCopier;
import org.slf4j.Logger;

import java.io.IOException;

public class LoggingTransferListener
        implements TransferListener {

    private final LoggerFactory loggerFactory;
    private final Logger log;

    private final String relPath;

    public LoggingTransferListener(LoggerFactory loggerFactory) {
        this("", loggerFactory);
    }

    private LoggingTransferListener(String relPath, LoggerFactory loggerFactory) {
        this.relPath = relPath;
        this.loggerFactory = loggerFactory;
        log = loggerFactory.getLogger(getClass());
    }

    @Override
    public TransferListener directory(String name) {
        log.debug("started transferring directory `{}`", name);
        return new LoggingTransferListener(relPath + name + "/", loggerFactory);
    }

    @Override
    public StreamCopier.Listener file(final String name, final long size) {
        final String path = relPath + name;
        log.debug("started transferring file `{}` ({} bytes)", path, size);
        return new StreamCopier.Listener() {
            @Override
            public void reportProgress(long transferred)
                    throws IOException {
                if (log.isTraceEnabled()) {
                    log.trace("transferred {}% of `{}`", ((transferred * 100) / size), path);
                }
            }
        };
    }

}
