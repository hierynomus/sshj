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
package net.schmizz.sshj.xfer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractFileTransfer {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    public static final LoggingTransferListener LOGGING_TRANSFER_LISTENER = new LoggingTransferListener();

    private volatile TransferListener transferListener = LOGGING_TRANSFER_LISTENER;

    public TransferListener getTransferListener() {
        return transferListener;
    }

    public void setTransferListener(TransferListener transferListener) {
        this.transferListener = (transferListener == null) ? LOGGING_TRANSFER_LISTENER : transferListener;
    }

}