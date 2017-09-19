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
import org.slf4j.Logger;

public abstract class AbstractFileTransfer {

    protected final LoggerFactory loggerFactory;
    protected final Logger log;

    private final LoggingTransferListener loggingTransferListener;

    private volatile TransferListener transferListener;

    protected AbstractFileTransfer(LoggerFactory loggerFactory) {
        this.loggerFactory = loggerFactory;
        log = loggerFactory.getLogger(getClass());
        loggingTransferListener = new LoggingTransferListener(loggerFactory);
        transferListener = loggingTransferListener;
    }

    public TransferListener getTransferListener() {
        return transferListener;
    }

    public void setTransferListener(TransferListener transferListener) {
        this.transferListener = (transferListener == null) ? loggingTransferListener : transferListener;
    }

}
