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

import java.util.Set;

public enum OpenMode {

    /** Open the file for reading. */
    READ(0x00000001),
    /**
     * Open the file for writing. If both this and {@link OpenMode#READ} are specified, the file is opened for both
     * reading and writing.
     */
    WRITE(0x00000002),
    /** Force all writes to append data at the end of the file. */
    APPEND(0x00000004),
    /**
     * If this flag is specified, then a new file will be created if one does not already exist (if {@link
     * OpenMode#TRUNC} is specified, the new file will be truncated to zero length if it previously exists).
     */
    CREAT(0x00000008),
    /**
     * Forces an existing file with the same name to be truncated to zero length when creating a file by specifying
     * {@link OpenMode#CREAT}. {@link OpenMode#CREAT} MUST also be specified if this flag is used.
     */
    TRUNC(0x00000010),
    /**
     * Causes the request to fail if the named file already exists. {@link OpenMode#CREAT} MUST also be specified if
     * this flag is used.
     */
    EXCL(0x00000020);

    private final int pflag;

    private OpenMode(int pflag) {
        this.pflag = pflag;
    }

    public static int toMask(Set<OpenMode> modes) {
        int mask = 0;
        for (OpenMode m : modes)
            mask |= m.pflag;
        return mask;
    }

}
