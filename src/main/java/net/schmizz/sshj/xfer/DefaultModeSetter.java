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

import java.io.File;
import java.io.IOException;


/**
 * Default implementation of {@link ModeSetter} attempts to preserve timestamps and permissions to the extent allowed by
 * Java File API.
 */
public class DefaultModeSetter
        implements ModeSetter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    public void setLastAccessedTime(File f, long t)
            throws IOException {
        // Can't do anything
    }

    @Override
    public void setLastModifiedTime(File f, long t)
            throws IOException {
        if (!f.setLastModified(t * 1000))
            log.warn("Could not set last modified time for {} to {}", f, t);
    }

    @Override
    public void setPermissions(File f, int perms)
            throws IOException {
        final boolean r = f.setReadable(FilePermission.USR_R.isIn(perms),
                                        !(FilePermission.OTH_R.isIn(perms) || FilePermission.GRP_R.isIn(perms)));
        final boolean w = f.setWritable(FilePermission.USR_W.isIn(perms),
                                        !(FilePermission.OTH_W.isIn(perms) || FilePermission.GRP_W.isIn(perms)));
        final boolean x = f.setExecutable(FilePermission.USR_X.isIn(perms),
                                          !(FilePermission.OTH_X.isIn(perms) || FilePermission.GRP_X.isIn(perms)));
        if (!(r && w && x))
            log.warn("Could not set permissions for {} to {}", f, Integer.toString(perms, 16));
    }

    @Override
    public boolean preservesTimes() {
        return true;
    }

}