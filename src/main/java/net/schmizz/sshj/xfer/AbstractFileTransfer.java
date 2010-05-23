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
package net.schmizz.sshj.xfer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractFileTransfer {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    public static final ModeGetter DEFAULT_MODE_SETTER = new DefaultModeGetter();
    public static final ModeSetter DEFAULT_MODE_GETTER = new DefaultModeSetter();
    public static final LoggingTransferListener LOGGING_TRANSFER_LISTENER = new LoggingTransferListener();

    private volatile ModeGetter modeGetter = DEFAULT_MODE_SETTER;
    private volatile ModeSetter modeSetter = DEFAULT_MODE_GETTER;
    private volatile TransferListener transferListener = LOGGING_TRANSFER_LISTENER;

    public void setModeGetter(ModeGetter modeGetter) {
        this.modeGetter = (modeGetter == null) ? DEFAULT_MODE_SETTER : modeGetter;
    }

    public ModeGetter getModeGetter() {
        return this.modeGetter;
    }

    public void setModeSetter(ModeSetter modeSetter) {
        this.modeSetter = (modeSetter == null) ? DEFAULT_MODE_GETTER : modeSetter;
    }

    public ModeSetter getModeSetter() {
        return this.modeSetter;
    }

    public TransferListener getTransferListener() {
        return transferListener;
    }

    public void setTransferListener(TransferListener transferListener) {
        this.transferListener = (transferListener == null) ? LOGGING_TRANSFER_LISTENER : transferListener;
    }

}
