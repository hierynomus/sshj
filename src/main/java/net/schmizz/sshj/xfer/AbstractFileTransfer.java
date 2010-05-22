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

    /** Logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());

    public static final ModeGetter defaultModeGetter = new DefaultModeGetter();
    public static final ModeSetter defaultModeSetter = new DefaultModeSetter();

    private volatile ModeGetter modeGetter = defaultModeGetter;
    private volatile ModeSetter modeSetter = defaultModeSetter;

    private volatile ProgressListener progressListener;

    public void setModeGetter(ModeGetter modeGetter) {
        this.modeGetter = (modeGetter == null) ? defaultModeGetter : modeGetter;
    }

    public ModeGetter getModeGetter() {
        return this.modeGetter;
    }

    public void setModeSetter(ModeSetter modeSetter) {
        this.modeSetter = (modeSetter == null) ? defaultModeSetter : modeSetter;
    }

    public ModeSetter getModeSetter() {
        return this.modeSetter;
    }

    public ProgressListener getProgressListener() {
        return progressListener;
    }

    public void setProgressListener(ProgressListener progressListener) {
        this.progressListener = progressListener;
    }

}
